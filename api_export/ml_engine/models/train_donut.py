"""
TraceX Donut Vision Transformer Fine-Tuning Pipeline
Fine-tunes naver-clova-ix/donut-base on email screenshots directly into structured JSON classification.
OCR-Free End-to-End Document Understanding.
"""

import os
import json
from typing import Dict, Any, List
from PIL import Image

try:
    import torch
    from torch.utils.data import Dataset
    from transformers import (
        DonutProcessor,
        VisionEncoderDecoderModel,
        Seq2SeqTrainingArguments,
        Seq2SeqTrainer
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class DonutEmailDataset(Dataset):
    """Custom PyTorch dataset for Donut training from metadata.jsonl."""

    def __init__(self, dataset_dir: str, processor: Any, max_length: int = 128):
        self.dataset_dir = dataset_dir
        self.raw_dir = os.path.join(dataset_dir, "raw")
        self.processor = processor
        self.max_length = max_length
        self.samples = []

        jsonl_path = os.path.join(dataset_dir, "metadata.jsonl")
        if os.path.exists(jsonl_path):
            with open(jsonl_path, "r") as f:
                for line in f:
                    if line.strip():
                        self.samples.append(json.loads(line.strip()))

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        item = self.samples[idx]
        image_path = os.path.join(self.raw_dir, item["file_name"])
        image = Image.open(image_path).convert("RGB")

        # Process image with Donut processor
        pixel_values = self.processor(image, return_tensors="pt").pixel_values.squeeze(0)

        # Target JSON sequence with task prompt
        target_seq = f"<s_phishing_analysis>{item['ground_truth']}</s>"
        labels = self.processor.tokenizer(
            target_seq,
            add_special_tokens=False,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        ).input_ids.squeeze(0)

        # Replace padding token id's with -100 so CrossEntropy loss ignores them
        labels[labels == self.processor.tokenizer.pad_token_id] = -100

        return {"pixel_values": pixel_values, "labels": labels}


def train_donut(
    dataset_dir: str,
    output_dir: str,
    model_name: str = "naver-clova-ix/donut-base",
    epochs: int = 3,
    batch_size: int = 2
) -> None:
    """Executes Donut fine-tuning loop."""
    if not TORCH_AVAILABLE:
        print("[-] PyTorch / Transformers not installed. Run pip install torch transformers datasets first.")
        return

    print(f"[*] Initializing Donut fine-tuning pipeline using {model_name}...")
    processor = DonutProcessor.from_pretrained(model_name)
    model = VisionEncoderDecoderModel.from_pretrained(model_name)

    # Add custom tokens if needed
    new_tokens = ["<s_phishing_analysis>"]
    processor.tokenizer.add_special_tokens({"additional_special_tokens": new_tokens})
    model.decoder.resize_token_embeddings(len(processor.tokenizer))

    # Freeze encoder to speed up training on lightweight hardware / hackathons
    for param in model.encoder.parameters():
        param.requires_grad = False

    dataset = DonutEmailDataset(dataset_dir, processor)
    print(f"[+] Loaded {len(dataset)} training samples.")

    training_args = Seq2SeqTrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        learning_rate=5e-5,
        weight_decay=0.01,
        logging_steps=5,
        save_strategy="epoch",
        fp16=torch.cuda.is_available(),
        predict_with_generate=True,
        push_to_hub=False,
        report_to="none"
    )

    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        tokenizer=processor.tokenizer
    )

    print("[*] Starting training...")
    trainer.train()

    print(f"[+] Model fine-tuned successfully. Saving to {output_dir}...")
    model.save_pretrained(output_dir)
    processor.save_pretrained(output_dir)
    print("[+] Donut weights and processor saved.")


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base, "data")
    save_dir = os.path.join(base, "models", "saved_models", "donut_phishing")
    train_donut(data_dir, save_dir, epochs=3)
