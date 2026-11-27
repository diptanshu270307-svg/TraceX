"""
TraceX Tabular Forensic Feature Extraction Engine
Extracts RFC 822 header security signals, authentication states, and domain linguistics using Pandas.
"""

import re
import math
import email
from email import policy
from email.parser import Parser
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


class HeaderForensicExtractor:
    """Extracts tabular forensic features from email headers and metadata."""

    KNOWN_TARGET_DOMAINS = [
        "sbi.co.in",
        "microsoft.com",
        "office.com",
        "google.com",
        "paypal.com",
        "apple.com",
        "amazon.com",
        "hdfcbank.com",
        "icicibank.com",
        "chase.com",
        "netflix.com"
    ]

    KNOWN_LEGITIMATE_DOMAINS = [
        "google.com", "youtube.com", "github.com", "microsoft.com",
        "apple.com", "amazon.com", "aws.amazon.com", "signup.aws", "linkedin.com",
        "twitter.com", "x.com", "internshala.com", "mail.internshala.com",
        "ultimate-guitar.com", "netflix.com", "spotify.com", "zoom.us",
        "notion.so", "slack.com", "atlassian.com", "dropbox.com", "stripe.com",
        "paypal.com", "stackoverflow.com", "coursera.org", "udemy.com"
    ]

    URGENT_KEYWORDS = [
        "urgent", "immediate", "action required", "suspended", "verify",
        "verification", "overdue", "invoice", "payroll", "warning",
        "unauthorized", "security alert", "compromised", "terminate",
        "confirm your identity", "wire transfer", "password", "within 24 hours"
    ]

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".click", ".live", ".support", ".work", ".test", ".buzz", ".loan"
    ]

    FEATURE_NAMES = [
        "spf_pass",
        "dkim_pass",
        "dmarc_pass",
        "domain_levenshtein",
        "domain_entropy",
        "has_punycode",
        "relay_hops",
        "display_name_spoof",
        "subject_urgency",
        "reply_to_mismatch",
        "suspicious_tld",
        "subdomain_depth"
    ]

    @staticmethod
    def shannon_entropy(string: str) -> float:
        """Calculates Shannon entropy of a domain string (high entropy indicates random/DGA domain)."""
        if not string:
            return 0.0
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum([p * math.log2(p) for p in prob if p > 0])

    @staticmethod
    def levenshtein_ratio(s1: str, s2: str) -> float:
        """Computes normalized Levenshtein similarity ratio between 0.0 and 1.0."""
        s1, s2 = s1.lower(), s2.lower()
        if s1 == s2:
            return 1.0
        m, n = len(s1), len(s2)
        if m == 0 or n == 0:
            return 0.0

        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                dp[i][j] = min(
                    dp[i - 1][j] + 1,      # Deletion
                    dp[i][j - 1] + 1,      # Insertion
                    dp[i - 1][j - 1] + cost # Substitution
                )

        return 1.0 - (dp[m][n] / max(m, n))

    def extract_from_dict(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts numerical/categorical features from metadata dictionary."""
        sender = meta.get("sender", "").strip()
        subject = meta.get("subject", "").strip().lower()
        body = meta.get("body_text", meta.get("body", "")).strip().lower()
        full_text = f"{subject} {body}"
        reply_to = meta.get("reply_to", "").strip()
        auth_results = meta.get("auth_results", "").upper()

        # Parse sender domain and display name
        display_name = ""
        email_addr = sender
        if "<" in sender and ">" in sender:
            parts = sender.split("<")
            display_name = parts[0].strip().strip('"').strip("'")
            email_addr = parts[1].split(">")[0].strip()

        domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
        reply_to_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else domain

        # Check if sender is from a known trusted domain
        is_known_trusted = any(
            domain == td or domain.endswith("." + td)
            for td in self.KNOWN_LEGITIMATE_DOMAINS
        )

        # 1. Authentication Status (SPF, DKIM, DMARC)
        # Default to 1 (PASS) unless explicitly failing
        if meta.get("spf") in ("FAIL", "SOFTFAIL") or "SPF=FAIL" in auth_results:
            spf_pass = 0
        else:
            spf_pass = 1

        if meta.get("dkim") == "FAIL" or "DKIM=FAIL" in auth_results:
            dkim_pass = 0
        else:
            dkim_pass = 1

        if meta.get("dmarc") == "FAIL" or "DMARC=FAIL" in auth_results:
            dmarc_pass = 0
        else:
            dmarc_pass = 1

        # If explicit auth booleans passed in meta
        if "spf_pass" in meta:
            spf_pass = int(meta["spf_pass"])
        if "dkim_pass" in meta:
            dkim_pass = int(meta["dkim_pass"])
        if "dmarc_pass" in meta:
            dmarc_pass = int(meta["dmarc_pass"])

        # 2. Domain Levenshtein ratio (is it spoofing a known brand?)
        best_ratio = 0.0
        for target in self.KNOWN_TARGET_DOMAINS:
            ratio = self.levenshtein_ratio(domain, target)
            if ratio > best_ratio and ratio < 1.0:
                best_ratio = ratio

        # 3. Domain Entropy & Punycode
        entropy = self.shannon_entropy(domain)
        has_punycode = 1 if "xn--" in domain else 0

        # 4. Relay Hops
        relay_hops = int(meta.get("relay_hops", meta.get("hops", 1)))

        # 5. Display Name Spoofing (e.g. Display Name says "Microsoft" or "SBI", but domain isn't)
        display_name_spoof = 0
        display_lower = display_name.lower()
        for brand in ["microsoft", "sbi", "paypal", "google", "apple", "it admin", "security team", "amazon"]:
            if brand in display_lower and brand not in domain:
                display_name_spoof = 1
                break

        # 6. Urgency (both Subject and Body)
        urgency_hits = sum(1 for kw in self.URGENT_KEYWORDS if kw in full_text)
        subject_urgency = min(1.0, urgency_hits * 0.25)

        # 7. Reply-To Mismatch
        reply_to_mismatch = 1 if (reply_to_domain and domain and reply_to_domain != domain and not is_known_trusted) else 0

        # 8. Suspicious TLD
        suspicious_tld = 1 if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS) else 0

        # Also check URLs in meta
        urls = meta.get("urls", [])
        for u in urls:
            if any(tld in u for tld in self.SUSPICIOUS_TLDS):
                suspicious_tld = 1

        # 9. Subdomain Depth
        subdomain_depth = max(0, domain.count(".") - 1)

        features = {
            "spf_pass": spf_pass,
            "dkim_pass": dkim_pass,
            "dmarc_pass": dmarc_pass,
            "domain_levenshtein": round(best_ratio, 4),
            "domain_entropy": round(entropy, 4),
            "has_punycode": has_punycode,
            "relay_hops": relay_hops,
            "display_name_spoof": display_name_spoof,
            "subject_urgency": round(subject_urgency, 4),
            "reply_to_mismatch": reply_to_mismatch,
            "suspicious_tld": suspicious_tld,
            "subdomain_depth": subdomain_depth
        }

        return features

    def extract_from_eml_file(self, eml_path: str) -> Dict[str, Any]:
        """Parses a raw RFC 822/5322 .eml file into structured metadata and features."""
        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")
        reply_to = msg.get("Reply-To", sender)
        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")

        # Count Received hops
        received_headers = msg.get_all("Received", [])
        relay_hops = max(1, len(received_headers))

        # Detect SPF status
        spf_status = "FAIL"
        auth_combined = f"{auth_results} {received_spf}".lower()
        if "spf=pass" in auth_combined or received_spf.lower().startswith("pass"):
            spf_status = "PASS"

        # Detect DKIM status
        dkim_status = "FAIL"
        if "dkim=pass" in auth_combined:
            dkim_status = "PASS"

        # Detect DMARC status
        dmarc_status = "FAIL"
        if "dmarc=pass" in auth_combined:
            dmarc_status = "PASS"

        # Extract body (plain text or html)
        body = ""
        html_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain" and not body:
                    try:
                        body = part.get_content()
                    except Exception:
                        pass
                elif ctype == "text/html" and not html_body:
                    try:
                        html_body = part.get_content()
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_content()
            except Exception:
                pass

        final_body = html_body or body or subject

        meta = {
            "sender": str(sender),
            "recipient": str(recipient),
            "subject": str(subject),
            "reply_to": str(reply_to),
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "hops": relay_hops,
            "auth_results": auth_results,
            "body": final_body
        }

        features = self.extract_from_dict(meta)
        return {"meta": meta, "features": features, "body": final_body}

    def to_dataframe(self, feature_dicts: List[Dict[str, Any]]) -> pd.DataFrame:
        """Converts a list of extracted feature dictionaries into a Pandas DataFrame."""
        df = pd.DataFrame(feature_dicts)
        for col in self.FEATURE_NAMES:
            if col not in df.columns:
                df[col] = 0
        return df[self.FEATURE_NAMES]
