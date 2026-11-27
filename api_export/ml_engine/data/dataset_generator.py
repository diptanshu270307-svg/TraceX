"""
TraceX Dataset Generator & Formatter
Bootstraps realistic multimodal datasets (email screenshots + paired RFC headers + metadata.jsonl)
for Donut Vision Transformer and XGBoost training.
"""

import os
import json
import random
from typing import List, Dict, Any

# Ensure Pillow is available or provide fallback image builder
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class DatasetGenerator:
    """Generates synthetic paired email screenshots and forensic headers."""

    SAMPLE_TEMPLATES = [
        # PHISHING
        {
            "class": "PHISHING",
            "subject": "Urgent: Corporate Account Verification Required",
            "sender": "State Bank Alerts <alerts@sbi-corp-demo.test>",
            "reply_to": "collector@offshore-drop.xyz",
            "target_brand": "sbi.co.in",
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "hops": 4,
            "fraud_score": 94,
            "banner_color": (220, 38, 38), # Red
            "body_lines": [
                "STATE BANK OF INDIA - SECURITY NOTIFICATION",
                "Your corporate internet banking portal has been temporarily locked.",
                "Mandatory BSA 2023 compliance re-verification is required within 2 hours.",
                "Failure to authenticate will lead to permanent account suspension.",
                ">> [CLICK HERE TO VERIFY CORPORATE CREDENTIALS] <<"
            ]
        },
        # IMPERSONATION
        {
            "class": "IMPERSONATION",
            "subject": "Mailbox Storage Limit Exceeded: Action Required",
            "sender": "IT Helpdesk Admin <security@m365-login-demo.test>",
            "reply_to": "admin-reply@m365-login-demo.test",
            "target_brand": "microsoft.com",
            "spf": "PASS",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "hops": 3,
            "fraud_score": 89,
            "banner_color": (234, 88, 12), # Orange
            "body_lines": [
                "MICROSOFT 365 ENTERPRISE CLOUD",
                "Your mailbox (49.8 GB / 50 GB) has exceeded safe storage threshold.",
                "Inbound emails are currently being queued and will be returned to sender.",
                "To prevent disruption, validate your corporate account credentials below.",
                ">> [EXPAND MAILBOX STORAGE NOW] <<"
            ]
        },
        # BEC (Business Email Compromise)
        {
            "class": "BEC",
            "subject": "Urgent: Confidential Vendor Wire Payment Authorization",
            "sender": "CEO Office <executive-office@company-corp.work>",
            "reply_to": "ceo-private@disposable-vault.xyz",
            "target_brand": "company.com",
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "hops": 5,
            "fraud_score": 96,
            "banner_color": (185, 28, 28), # Dark Red
            "body_lines": [
                "CONFIDENTIAL & TIME SENSITIVE",
                "Team, I am currently in closed-door M&A meetings and cannot take calls.",
                "We need to settle the outstanding retainer for Vendor Acquisition Q3 immediately.",
                "Please process an expedited RTGS transfer of ₹28,50,000 to the attached account.",
                "Confirm once executed. Do not discuss over Slack until public release."
            ]
        },
        # LEGITIMATE
        {
            "class": "LEGITIMATE",
            "subject": "Monthly Jira Cloud Platform Digest & Sprint Summary",
            "sender": "Atlassian Cloud <notifications@atlassian.com>",
            "reply_to": "no-reply@atlassian.com",
            "target_brand": "atlassian.com",
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS",
            "hops": 2,
            "fraud_score": 12,
            "banner_color": (37, 99, 235), # Blue
            "body_lines": [
                "ATLASSIAN JIRA CLOUD NOTIFICATION",
                "Here is your weekly summary of closed issues and sprint velocity.",
                "34 user stories resolved across active development boards.",
                "System maintenance window scheduled for Sunday 02:00 UTC (zero downtime).",
                ">> [VIEW COMPLETE SPRINT REPORT] <<"
            ]
        },
        # LEGITIMATE 2
        {
            "class": "LEGITIMATE",
            "subject": "AWS Billing Notification: August Statement Available",
            "sender": "Amazon Web Services <no-reply-aws@amazon.com>",
            "reply_to": "no-reply@amazon.com",
            "target_brand": "amazon.com",
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS",
            "hops": 2,
            "fraud_score": 8,
            "banner_color": (16, 185, 129), # Green
            "body_lines": [
                "AMAZON WEB SERVICES INVOICE",
                "Your AWS monthly invoice statement is now ready to download in AWS Console.",
                "Account ID: 4892-1209-3891. Total Amount Due: $148.20.",
                "Automatic payment will be processed via your primary payment method.",
                ">> [ACCESS AWS BILLING DASHBOARD] <<"
            ]
        }
    ]

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.raw_dir = os.path.join(output_dir, "raw")
        self.jsonl_path = os.path.join(output_dir, "metadata.jsonl")
        self.full_dataset_path = os.path.join(output_dir, "multimodal_dataset.json")

        os.makedirs(self.raw_dir, exist_ok=True)

    def _render_email_screenshot(self, filepath: str, template: Dict[str, Any]) -> None:
        """Renders synthetic email visual screenshot with banner, typography, and fake CTA buttons."""
        if not PIL_AVAILABLE:
            with open(filepath, "wb") as f:
                header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
                meta_tag = f"<!-- TRACEX_SAMPLE:{template['subject']}:{filepath} -->".encode("utf-8")
                f.write(header + meta_tag)
            return

        width, height = 800, 600
        bg_color = (248, 250, 252) # Clean slate white
        image = Image.new("RGB", (width, height), bg_color)
        draw = ImageDraw.Draw(image)

        # 1. Top Email Client Header Bar
        draw.rectangle([(0, 0), (width, 80)], fill=(15, 23, 42)) # Dark slate
        # Simulated header text
        draw.text((25, 20), f"From: {template['sender']}", fill=(226, 232, 240))
        draw.text((25, 45), f"Subject: {template['subject']}", fill=(148, 163, 184))

        # 2. Alert / Urgency Banner
        banner_fill = template["banner_color"]
        draw.rectangle([(25, 100), (width - 25, 145)], fill=banner_fill)
        draw.text((45, 115), f"SECURITY CLASSIFICATION: {template['class']}", fill=(255, 255, 255))

        # 3. Email Body Container
        draw.rectangle([(25, 160), (width - 25, 520)], fill=(255, 255, 255), outline=(203, 213, 225))

        # Body Text
        y_cursor = 190
        for line in template["body_lines"]:
            if ">>" in line: # Simulated CTA Button
                draw.rectangle([(50, y_cursor - 5), (width - 50, y_cursor + 35)], fill=banner_fill)
                draw.text((65, y_cursor + 5), line, fill=(255, 255, 255))
                y_cursor += 50
            else:
                draw.text((50, y_cursor), line, fill=(30, 41, 59))
                y_cursor += 32

        # Footer
        draw.text((25, 550), "Confidentiality Notice: TraceX Automated Forensic Ingestion Snapshot", fill=(148, 163, 184))

        image.save(filepath, "PNG")

    def generate(self, num_samples: int = 60) -> str:
        """Generates synthetic balanced dataset."""
        print(f"[*] Generating {num_samples} multimodal email samples...")
        jsonl_records = []
        full_records = []

        for i in range(num_samples):
            template = random.choice(self.SAMPLE_TEMPLATES)
            file_name = f"email_{i:04d}.png"
            img_path = os.path.join(self.raw_dir, file_name)

            # Render image
            self._render_email_screenshot(img_path, template)

            # Metadata for Donut fine-tuning
            donut_ground_truth = {
                "class": template["class"].lower(),
                "fraud_score": template["fraud_score"],
                "target_brand": template["target_brand"]
            }

            jsonl_records.append({
                "file_name": file_name,
                "ground_truth": json.dumps(donut_ground_truth)
            })

            # Full record for XGBoost training
            full_records.append({
                "id": f"SAMPLE-{i:04d}",
                "file_path": img_path,
                "file_name": file_name,
                "class": template["class"],
                "fraud_score": template["fraud_score"],
                "sender": template["sender"],
                "reply_to": template["reply_to"],
                "subject": template["subject"],
                "spf": template["spf"],
                "dkim": template["dkim"],
                "dmarc": template["dmarc"],
                "hops": template["hops"],
                "target_brand": template["target_brand"]
            })

        # Save metadata.jsonl for Donut
        with open(self.jsonl_path, "w") as f:
            for rec in jsonl_records:
                f.write(json.dumps(rec) + "\n")

        # Save full multimodal dataset JSON
        with open(self.full_dataset_path, "w") as f:
            json.dump(full_records, f, indent=2)

        print(f"[+] Dataset successfully generated at {self.output_dir}:")
        print(f"    - {len(full_records)} screenshots rendered in {self.raw_dir}")
        print(f"    - Donut metadata saved to {self.jsonl_path}")
        print(f"    - Full multimodal metadata saved to {self.full_dataset_path}")

        return self.full_dataset_path


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base, "data")
    generator = DatasetGenerator(target_dir)
    generator.generate(num_samples=80)
