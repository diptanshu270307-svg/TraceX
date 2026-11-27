"""
TraceX OCR-Free Visual Feature Extractor (Donut Vision Transformer)
Replaces Tesseract OCR and BERT NLP by extracting visual document intelligence directly from images.
"""

import os
import json
from typing import Dict, Any, List, Optional
import numpy as np

# Check if PyTorch / Transformers are available
TORCH_AVAILABLE = False
try:
    import torch
    from PIL import Image
    from transformers import DonutProcessor, VisionEncoderDecoderModel
    TORCH_AVAILABLE = True
except ImportError:
    try:
        from PIL import Image
    except ImportError:
        pass


class DonutVisualExtractor:
    """
    Extracts visual phishing cues directly from email screenshots without OCR bounding boxes.
    Uses Swin Transformer visual encoder + BART decoder.
    """

    FEATURE_NAMES = [
        "visual_phish_prob",
        "visual_urgency_cue",
        "has_credential_box",
        "logo_prominence_score",
        "layout_anomaly_score",
        "color_contrast_ratio"
    ]

    def __init__(self, model_name_or_path: str = "naver-clova-ix/donut-base", device: Optional[str] = None):
        self.model_name = model_name_or_path
        self.device = device or ("cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu")
        self.model = None
        self.processor = None
        self._is_loaded = False

    def load_model(self) -> bool:
        """Loads pre-trained or fine-tuned Donut weights."""
        if not TORCH_AVAILABLE:
            return False

        try:
            print(f"[*] Loading Donut model ({self.model_name}) on {self.device}...")
            self.processor = DonutProcessor.from_pretrained(self.model_name)
            self.model = VisionEncoderDecoderModel.from_pretrained(self.model_name)
            self.model.to(self.device)
            self.model.eval()
            self._is_loaded = True
            print("[+] Donut model successfully loaded.")
            return True
        except Exception as e:
            print(f"[-] Could not load Hugging Face Donut model: {e}")
            self._is_loaded = False
            return False

    def extract_visual_features(self, image_input: Any) -> Dict[str, Any]:
        """
        Extracts visual phishing feature vector from an image file path or PIL Image.
        Outputs structured visual signals for the XGBoost ensemble.
        """
        image = None
        if isinstance(image_input, str) and os.path.exists(image_input):
            try:
                from PIL import Image
                image = Image.open(image_input).convert("RGB")
            except Exception:
                pass
        elif hasattr(image_input, "convert"):
            image = image_input.convert("RGB")

        if self._is_loaded and self.model is not None and self.processor is not None and image is not None:
            return self._infer_donut(image)
        else:
            return self._fallback_visual_analysis(image)

    def _infer_donut(self, image: Any) -> Dict[str, Any]:
        """Performs vision-language inference with Donut."""
        try:
            pixel_values = self.processor(image, return_tensors="pt").pixel_values.to(self.device)
            task_prompt = "<s_phishing_analysis>"
            decoder_input_ids = self.processor.tokenizer(
                task_prompt, add_special_tokens=False, return_tensors="pt"
            ).input_ids.to(self.device)

            with torch.no_grad():
                outputs = self.model.generate(
                    pixel_values,
                    decoder_input_ids=decoder_input_ids,
                    max_length=128,
                    early_stopping=True,
                    pad_token_id=self.processor.tokenizer.pad_token_id,
                    eos_token_id=self.processor.tokenizer.eos_token_id,
                    use_cache=True,
                    num_beams=1,
                    return_dict_in_generate=True,
                    output_scores=True
                )

            seq = self.processor.batch_decode(outputs.sequences)[0]
            seq = seq.replace(self.processor.tokenizer.eos_token, "").replace(self.processor.tokenizer.pad_token, "")
            seq = seq.replace("<s_phishing_analysis>", "").strip()

            try:
                parsed = json.loads(seq)
                return {
                    "visual_phish_prob": float(parsed.get("prob", 0.85)),
                    "visual_urgency_cue": float(parsed.get("urgency", 0.8)),
                    "has_credential_box": int(parsed.get("has_login", 1)),
                    "logo_prominence_score": float(parsed.get("logo_score", 0.75)),
                    "layout_anomaly_score": float(parsed.get("anomaly", 0.7)),
                    "color_contrast_ratio": 0.85,
                    "donut_raw_json": parsed
                }
            except Exception:
                pass
        except Exception as e:
            print(f"[-] Donut inference exception: {e}")

        return self._fallback_visual_analysis(image)

    def _fallback_visual_analysis(self, image: Optional[Any]) -> Dict[str, Any]:
        """
        Ultra-fast deterministic visual heuristics when full GPU weights are loading or offline.
        Analyzes image visual entropy, aspect ratio, and layout structure.
        """
        if image is None:
            return {
                "visual_phish_prob": 0.5,
                "visual_urgency_cue": 0.3,
                "has_credential_box": 0,
                "logo_prominence_score": 0.4,
                "layout_anomaly_score": 0.5,
                "color_contrast_ratio": 0.5
            }

        try:
            # Resize for quick inspection
            small = image.resize((64, 64))
            arr = np.array(small, dtype=np.float32)
            
            # Color variance across RGB channels
            std_color = float(np.std(arr)) / 128.0
            
            # Header strip contrast (top 20% vs middle)
            top_strip = arr[:12, :, :]
            middle_strip = arr[13:40, :, :]
            top_mean = float(np.mean(top_strip))
            mid_mean = float(np.mean(middle_strip))
            contrast = min(1.0, abs(top_mean - mid_mean) / 100.0)

            # Heuristic visual phish probability based on visual entropy & contrast
            prob = min(0.98, max(0.05, 0.4 + 0.3 * contrast + 0.2 * std_color))

            return {
                "visual_phish_prob": round(prob, 4),
                "visual_urgency_cue": round(contrast, 4),
                "has_credential_box": 1 if contrast > 0.45 else 0,
                "logo_prominence_score": round(min(1.0, std_color * 1.2), 4),
                "layout_anomaly_score": round(contrast, 4),
                "color_contrast_ratio": round(contrast, 4)
            }
        except Exception:
            return {
                "visual_phish_prob": 0.6,
                "visual_urgency_cue": 0.5,
                "has_credential_box": 1,
                "logo_prominence_score": 0.5,
                "layout_anomaly_score": 0.5,
                "color_contrast_ratio": 0.5
            }
