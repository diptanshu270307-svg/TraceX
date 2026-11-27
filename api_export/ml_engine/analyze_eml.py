"""
TraceX .EML Forensic Ingestion & Multimodal Analyzer
Parses raw .eml emails, renders visual screenshots for Donut ViT, runs XGBoost scoring,
and archives the artifact to AWS S3 & DynamoDB with SHA-256 evidence seals.
"""

import os
import sys
import json
import argparse
from typing import Optional

# Ensure project root in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ml_engine.pipeline import TraceXMLPipeline
from ml_engine.features.header_extractor import HeaderForensicExtractor

try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def render_eml_to_image(sender: str, subject: str, body: str, output_path: str) -> str:
    """Renders the parsed email content into an image screenshot for the Donut Vision Transformer."""
    if not PIL_AVAILABLE:
        # Fallback binary placeholder
        with open(output_path, "wb") as f:
            header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
            f.write(header + f"<!-- TRACEX_EML:{subject} -->".encode("utf-8"))
        return output_path

    width, height = 800, 600
    image = Image.new("RGB", (width, height), (248, 250, 252))
    draw = ImageDraw.Draw(image)

    # 1. Header Bar
    draw.rectangle([(0, 0), (width, 80)], fill=(15, 23, 42))
    draw.text((25, 20), f"From: {sender[:70]}", fill=(226, 232, 240))
    draw.text((25, 45), f"Subject: {subject[:70]}", fill=(148, 163, 184))

    # 2. Email Body Container
    draw.rectangle([(25, 100), (width - 25, 520)], fill=(255, 255, 255), outline=(203, 213, 225))

    # Clean body lines
    clean_lines = [line.strip() for line in body.split("\n") if line.strip()][:10]
    y_cursor = 120
    for line in clean_lines:
        draw.text((45, y_cursor), line[:80], fill=(30, 41, 59))
        y_cursor += 30

    # Watermark / Footer
    draw.text((25, 550), "TraceX Forensics: Rendered for Donut Vision Transformer", fill=(148, 163, 184))

    image.save(output_path, "PNG")
    return output_path


def analyze_eml_file(eml_path: str):
    if not os.path.exists(eml_path):
        print(f"[-] Error: File '{eml_path}' not found.")
        sys.exit(1)

    print("=" * 75)
    print(f"  TRACEX CYBER-FORENSIC .EML INGESTION & CLOUD ANALYZER")
    print(f"  Target File: {eml_path}")
    print("=" * 75)

    # 1. Parse RFC 822/5322 Headers & Body
    print("\n[*] [Stage 1/4] Parsing RFC 822 Email Headers & Protocol Security...")
    extractor = HeaderForensicExtractor()
    parsed = extractor.extract_from_eml_file(eml_path)
    meta = parsed["meta"]
    features = parsed["features"]
    body = parsed["body"]

    print(f"    • Sender:     {meta['sender']}")
    print(f"    • Recipient:  {meta['recipient']}")
    print(f"    • Subject:    {meta['subject']}")
    print(f"    • Relay Hops: {meta['hops']} server hop(s)")
    print(f"    • Auth Flags: SPF={meta['spf']} | DKIM={meta['dkim']} | DMARC={meta['dmarc']}")

    # 2. Render Image for Donut Vision Transformer
    print("\n[*] [Stage 2/4] Headless Rendering Email Screenshot for Donut ViT...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    render_dir = os.path.join(base_dir, "data", "raw")
    os.makedirs(render_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(eml_path))[0]
    screenshot_path = os.path.join(render_dir, f"{base_name}_render.png")

    render_eml_to_image(meta["sender"], meta["subject"], body, screenshot_path)
    print(f"[+] Rendered email screenshot to: {screenshot_path}")

    # 3. Execute Multimodal Inference & AWS Cloud Archive
    print("\n[*] [Stage 3/4] Fusing Visual ViT + Tabular XGBoost & Archiving to AWS...")
    pipeline = TraceXMLPipeline()
    verdict = pipeline.predict(
        image_path_or_obj=screenshot_path,
        metadata_or_headers=meta,
        sender=meta["sender"],
        recipient=meta["recipient"],
        subject=meta["subject"]
    )

    # 4. Display Comprehensive Forensic Report
    print("\n" + "=" * 75)
    print("  TRACEX CYBER-FORENSIC VERDICT REPORT")
    print("=" * 75)

    color_tag = "🔴" if verdict["risk_level"] in ["CRITICAL", "HIGH"] else "🟢"
    print(f"\n{color_tag} VERDICT: [{verdict['risk_level']}] {verdict['classification']}")
    print(f"   • Fraud Score:       {verdict['fraud_score']} / 100")
    print(f"   • Model Confidence:  {verdict['confidence'] * 100:.2f}%")

    print("\n🛡️ PROTOCOL AUTHENTICATION MATRIX:")
    print(f"   • SPF:               {verdict['forensic_breakdown']['spf']}")
    print(f"   • DKIM:              {verdict['forensic_breakdown']['dkim']}")
    print(f"   • DMARC:             {verdict['forensic_breakdown']['dmarc']}")
    print(f"   • Relay Server Hops: {verdict['forensic_breakdown']['relay_hops']}")

    print("\n🔍 FORENSIC LINGUISTICS & VISION:")
    print(f"   • Domain Levenshtein:{verdict['forensic_breakdown']['domain_levenshtein']}")
    print(f"   • Domain Entropy:    {verdict['forensic_breakdown']['domain_entropy']}")
    print(f"   • Visual Phish Prob: {verdict['forensic_breakdown']['visual_phish_prob'] * 100:.1f}%")

    print("\n☁️ AWS CLOUD STORAGE & LEGAL CHAIN OF CUSTODY:")
    print(f"   • Scan ID:           {verdict['scan_id']}")
    print(f"   • SHA-256 Checksum:  {verdict['sha256_hash']}")
    print(f"   • AWS S3 URI:        {verdict['s3_uri']}")
    print(f"   • DynamoDB Evidence: {verdict['evidence_id']}")
    print(f"   • Cryptographic Seal:{verdict['cryptographic_seal']}")
    print("=" * 75)

    return verdict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a raw .eml email with TraceX AI & AWS")
    parser.add_argument("file", nargs="?", help="Path to .eml file")
    args = parser.parse_args()

    if args.file:
        analyze_eml_file(args.file)
    else:
        print("Usage: python ml_engine/analyze_eml.py <path_to_email.eml>")
