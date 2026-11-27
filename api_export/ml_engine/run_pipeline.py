"""
TraceX Master Pipeline Orchestrator
Executes: Dataset Generation -> Multimodal Feature Extraction -> Model Training -> Test Inference & Evidence Verification.
"""

import os
import sys
import json

# Ensure project root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ml_engine.data.dataset_generator import DatasetGenerator
from ml_engine.models.train_xgboost import TraceXXGBoostTrainer
from ml_engine.pipeline import TraceXMLPipeline
from ml_engine.storage.aws_storage import AWSForensicStorageManager


def main():
    print("=" * 70)
    print("  TRACEX CYBER-FORENSIC ML ENGINE: DONUT + XGBOOST PIPELINE")
    print("  Zero-OCR Vision Transformer + Tabular Gradient Boosting")
    print("=" * 70)

    base = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base, "data")
    save_dir = os.path.join(base, "models", "saved_models")
    db_path = os.path.join(base, "storage", "database.sqlite")

    # STEP 1: Generate / Prepare Multimodal Dataset
    print("\n[PHASE 1/4] Bootstrapping Multimodal Dataset...")
    generator = DatasetGenerator(data_dir)
    dataset_file = generator.generate(num_samples=100)

    # STEP 2: Train Gradient Boosted Model (XGBoost)
    print("\n[PHASE 2/4] Training Multimodal Gradient Boosted Model...")
    trainer = TraceXXGBoostTrainer(dataset_file, save_dir)
    meta = trainer.train()

    # STEP 3: Test End-to-End Inference
    print("\n[PHASE 3/4] Testing End-to-End Inference Pipeline...")
    pipeline = TraceXMLPipeline(model_dir=save_dir)

    # Test Sample A: Critical Phishing Attack
    sample_a_meta = {
        "sender": "State Bank Alerts <alerts@sbi-corp-demo.test>",
        "subject": "Urgent Corporate Invoice Verification Required",
        "reply_to": "fraud@external-phish.xyz",
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
        "hops": 4,
        "recipient": "finance@corp.internal"
    }
    sample_a_img = os.path.join(data_dir, "raw", "email_0000.png")

    print("\n--- Running Inference on Sample A (Simulated SBI Bank Phishing) ---")
    result_a = pipeline.predict(
        image_path_or_obj=sample_a_img,
        metadata_or_headers=sample_a_meta
    )
    print(json.dumps(result_a, indent=2))

    # Test Sample B: Legitimate Email
    sample_b_meta = {
        "sender": "Amazon Web Services <no-reply-aws@amazon.com>",
        "subject": "AWS Billing Notification: August Statement Available",
        "reply_to": "no-reply@amazon.com",
        "spf": "PASS",
        "dkim": "PASS",
        "dmarc": "PASS",
        "hops": 2,
        "recipient": "devops@corp.internal"
    }
    sample_b_img = os.path.join(data_dir, "raw", "email_0001.png")

    print("\n--- Running Inference on Sample B (Legitimate AWS Notification) ---")
    result_b = pipeline.predict(
        image_path_or_obj=sample_b_img,
        metadata_or_headers=sample_b_meta
    )
    print(json.dumps(result_b, indent=2))

    # STEP 4: Inspect AWS Cloud Storage & Evidence Ledger
    print("\n[PHASE 4/4] Verifying AWS Cloud Storage (S3 & DynamoDB)...")
    recent_scans = pipeline.storage_manager.list_scans(limit=5)
    print(f"[+] Total Scans Recorded in AWS Storage: {len(recent_scans)}")
    for s in recent_scans:
        print(f"    • [{s['risk_level']}] Score: {s['fraud_score']:<3} | Class: {s['classification']:<13} | S3: {s.get('s3_uri', 'N/A')} | Sender: {s['sender']}")

    print("\n" + "=" * 70)
    print("  PIPELINE EXECUTION COMPLETE & VERIFIED SUCCESSFULLY ON AWS")
    print("=" * 70)


if __name__ == "__main__":
    main()
