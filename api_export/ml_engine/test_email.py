"""
TraceX Interactive AI Model Tester & Stress-Test Suite
Allows custom manual testing and runs 4 adversarial edge-case scenarios against the trained model.
"""

import os
import sys
import json
import argparse

# Ensure project root in sys.path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from ml_engine.pipeline import TraceXMLPipeline

# 4 Adversarial Edge-Case Scenarios
STRESS_TEST_CASES = [
    {
        "name": "Scenario 1: Display Name Spoofing (IT Admin Impersonation)",
        "description": "Sender display name claims to be IT Admin, but domain is external with failing DMARC.",
        "meta": {
            "sender": '"IT Helpdesk Security" <admin@m365-login-demo.test>',
            "subject": "Immediate Action: Your Microsoft 365 Password Expires Today",
            "reply_to": "collector@offshore-harvest.xyz",
            "spf": "PASS",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "hops": 3
        },
        "expected_class": "IMPERSONATION",
        "expected_risk": "CRITICAL / HIGH"
    },
    {
        "name": "Scenario 2: Typosquatting / Brand Lookalike Domain (SBI Phishing)",
        "description": "Domain mimics sbi.co.in using lookalike domain with urgency keywords.",
        "meta": {
            "sender": "State Bank Alerts <alerts@sbi-corp-demo.test>",
            "subject": "Urgent Corporate Invoice Verification Required",
            "reply_to": "fraud@external-phish.xyz",
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "hops": 4
        },
        "expected_class": "PHISHING",
        "expected_risk": "CRITICAL"
    },
    {
        "name": "Scenario 3: BEC Executive Wire Fraud (No Links, Pure Social Engineering)",
        "description": "Impersonates CEO requesting confidential RTGS wire transfer.",
        "meta": {
            "sender": "CEO Office <executive-office@company-corp.work>",
            "subject": "Urgent: Confidential Vendor Wire Payment Authorization",
            "reply_to": "ceo-private@disposable-vault.xyz",
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "hops": 5
        },
        "expected_class": "BEC",
        "expected_risk": "CRITICAL"
    },
    {
        "name": "Scenario 4: Tricky Legitimate Alert (Urgent Words but 100% Valid Protocol Auth)",
        "description": "Real security alert with urgency keywords, but passes SPF, DKIM, and DMARC from authentic domain.",
        "meta": {
            "sender": "Google Security <no-reply@accounts.google.com>",
            "subject": "Security Alert: New sign-in detected from unknown device",
            "reply_to": "no-reply@accounts.google.com",
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS",
            "hops": 2
        },
        "expected_class": "LEGITIMATE",
        "expected_risk": "LOW"
    }
]


def run_stress_test():
    print("=" * 75)
    print("  TRACEX AI MODEL TEST BENCHMARK: 4 ADVERSARIAL ATTACK SCENARIOS")
    print("=" * 75)

    pipeline = TraceXMLPipeline()
    passed_tests = 0

    for i, test in enumerate(STRESS_TEST_CASES, 1):
        print(f"\n[TEST {i}/4] {test['name']}")
        print(f"Details: {test['description']}")
        print(f"From:    {test['meta']['sender']}")
        print(f"Subject: {test['meta']['subject']}")

        verdict = pipeline.predict(
            image_path_or_obj=None,
            metadata_or_headers=test["meta"]
        )

        fraud_score = verdict["fraud_score"]
        classification = verdict["classification"]
        risk_level = verdict["risk_level"]
        confidence = verdict["confidence"]
        seal = verdict["cryptographic_seal"][:16] + "..."

        print(f"\n>> PREDICTED:")
        print(f"   • Fraud Score:   {fraud_score}/100")
        print(f"   • Risk Level:    {risk_level}")
        print(f"   • Class:         {classification} (Expected: {test['expected_class']})")
        print(f"   • Confidence:    {confidence * 100:.2f}%")
        print(f"   • Evidence Seal: {seal}")

        # Validation rule
        is_success = (
            (test["expected_class"] == "LEGITIMATE" and risk_level == "LOW") or
            (test["expected_class"] != "LEGITIMATE" and risk_level in ["CRITICAL", "HIGH"])
        )

        if is_success:
            print("   Status: [PASS] Model correctly identified threat severity.")
            passed_tests += 1
        else:
            print("   Status: [REVIEW] Model deviated from expected baseline.")

    print("\n" + "=" * 75)
    print(f"  BENCHMARK SUMMARY: {passed_tests}/4 TESTS PASSED ({passed_tests/4*100:.1f}%)")
    print("=" * 75)


def run_custom_test(sender, subject, spf, dkim, dmarc):
    pipeline = TraceXMLPipeline()
    meta = {
        "sender": sender,
        "subject": subject,
        "spf": spf.upper(),
        "dkim": dkim.upper(),
        "dmarc": dmarc.upper(),
        "hops": 3
    }

    print(f"\n[*] Evaluating Custom Email:")
    print(f"    From:    {sender}")
    print(f"    Subject: {subject}")
    print(f"    Auth:    SPF={spf} | DKIM={dkim} | DMARC={dmarc}")

    verdict = pipeline.predict(image_path_or_obj=None, metadata_or_headers=meta)
    print("\n[+] TraceX Verdict:")
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TraceX AI Model Tester")
    parser.add_argument("--sender", type=str, help="Sender email address")
    parser.add_argument("--subject", type=str, help="Email subject line")
    parser.add_argument("--spf", type=str, default="FAIL", help="SPF status: PASS or FAIL")
    parser.add_argument("--dkim", type=str, default="FAIL", help="DKIM status: PASS or FAIL")
    parser.add_argument("--dmarc", type=str, default="FAIL", help="DMARC status: PASS or FAIL")

    args = parser.parse_args()

    if args.sender and args.subject:
        run_custom_test(args.sender, args.subject, args.spf, args.dkim, args.dmarc)
    else:
        run_stress_test()
