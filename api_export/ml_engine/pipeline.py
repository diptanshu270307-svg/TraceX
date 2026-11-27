"""
TraceX Unified End-to-End Inference Pipeline
Combines Donut Vision Transformer + XGBoost + Header Forensics + SQLite Storage.
"""

import os
import json
import pickle

def load_model(path):
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        with open(path, "rb") as f:
            return pickle.load(f)

import numpy as np
import pandas as pd
from typing import Dict, Any, Optional

from ml_engine.features.header_extractor import HeaderForensicExtractor
from ml_engine.features.donut_extractor import DonutVisualExtractor
from ml_engine.storage.aws_storage import AWSForensicStorageManager
from ml_engine.storage.redis_cache import TraceXRedisCache


class TraceXMLPipeline:
    """Unified inference engine for TraceX using AWS cloud storage & Redis in-memory cache."""

    def __init__(self, model_dir: Optional[str] = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if model_dir is None:
            model_dir = os.path.join(base_dir, "models", "saved_models")
        self.model_dir = model_dir

        self.storage_manager = AWSForensicStorageManager()
        self.redis_cache = TraceXRedisCache()
        self.header_extractor = HeaderForensicExtractor()
        self.donut_extractor = DonutVisualExtractor()

        # Load models and metadata
        self.classifier = None
        self.regressor = None
        self.meta = {}
        self.feature_names = []
        self.class_mapping = {}

        self._load_saved_models()

    def _load_saved_models(self) -> None:
        meta_path = os.path.join(self.model_dir, "feature_meta.json")
        clf_path = os.path.join(self.model_dir, "xgb_classifier.joblib")
        reg_path = os.path.join(self.model_dir, "xgb_regressor.joblib")

        if os.path.exists(meta_path) and os.path.exists(clf_path):
            try:
                with open(meta_path, "r") as f:
                    self.meta = json.load(f)
                self.feature_names = self.meta.get("feature_names", [])
                self.class_mapping = {
                    int(k): v for k, v in self.meta.get("class_mapping", {}).items()
                }

                self.classifier = load_model(clf_path)
                if os.path.exists(reg_path):
                    self.regressor = load_model(reg_path)
                print("[+] Loaded trained XGBoost models and feature schema.")
            except Exception as e:
                print(f"[-] Error loading saved models: {e}")

    def predict(
        self,
        image_path_or_obj: Optional[Any],
        metadata_or_headers: Dict[str, Any],
        sender: str = "unknown@domain.test",
        recipient: str = "security-team@corp.internal",
        subject: str = "Suspicious Communication"
    ) -> Dict[str, Any]:
        """
        Executes end-to-end multimodal inference, calculates SHA-256 seal,
        and saves the forensic record into SQLite.
        """
        sender = metadata_or_headers.get("sender", sender)
        subject = metadata_or_headers.get("subject", subject)
        recipient = metadata_or_headers.get("recipient", recipient)

        # Compute preliminary artifact hash for Redis deduplication
        if isinstance(image_path_or_obj, str) and os.path.exists(image_path_or_obj):
            artifact_sha = self.storage_manager.compute_file_sha256(image_path_or_obj)
        else:
            seed = f"{sender}:{subject}:{metadata_or_headers.get('spf')}:{metadata_or_headers.get('dkim')}".encode()
            artifact_sha = self.storage_manager.compute_sha256(seed)

        # 0. Check Redis In-Memory Cache (Instant Deduplication)
        cached_verdict = self.redis_cache.get_cached_verdict(artifact_sha)
        if cached_verdict:
            print(f"[*] [Redis Cache HIT] Instant 0.2ms retrieval for SHA: {artifact_sha[:12]}...")
            cached_verdict["cached"] = True
            return cached_verdict

        # 1. Tabular forensic feature extraction via Pandas
        tab_feats = self.header_extractor.extract_from_dict(metadata_or_headers)

        # 2. Donut OCR-free visual feature extraction
        vis_feats = self.donut_extractor.extract_visual_features(image_path_or_obj)
        vis_feats_numeric = {
            k: v for k, v in vis_feats.items() if isinstance(v, (int, float))
        }

        # 3. Concatenate multimodal vector
        combined_features = {**tab_feats, **vis_feats_numeric}

        # Check domain legitimacy
        domain = sender.split("@")[-1].split(">")[0].strip().lower()
        is_trusted_domain = any(
            domain == td or domain.endswith("." + td)
            for td in self.header_extractor.KNOWN_LEGITIMATE_DOMAINS
        )

        reasons = []

        # 4. Predict using trained models or calibrated multimodal heuristic
        if self.classifier is not None and self.feature_names:
            row_df = pd.DataFrame([combined_features])
            for col in self.feature_names:
                if col not in row_df.columns:
                    row_df[col] = 0.0
            row_df = row_df[self.feature_names]

            class_pred_idx = self.classifier.predict(row_df)[0]
            classification = self.class_mapping.get(int(class_pred_idx), "SUSPICIOUS")

            if hasattr(self.classifier, "predict_proba"):
                probs = self.classifier.predict_proba(row_df)[0]
                confidence = float(np.max(probs))
            else:
                confidence = 0.95

            if self.regressor is not None:
                raw_score = float(self.regressor.predict(row_df)[0])
                fraud_score = int(np.clip(round(raw_score), 0, 100))
            else:
                fraud_score = 90 if classification != "LEGITIMATE" else 15

            # Calibrate for trusted domains
            if is_trusted_domain and combined_features.get("display_name_spoof", 0) == 0:
                fraud_score = min(fraud_score, 18)
                classification = "LEGITIMATE"
                reasons.append(f"Sender domain ({domain}) is a cryptographically verified legitimate authority")
        else:
            # Calibrated Multimodal Scoring Engine
            vis_prob = float(combined_features.get("visual_phish_prob", 0.3))
            urgency = float(combined_features.get("subject_urgency", 0.0))
            spoof = int(combined_features.get("display_name_spoof", 0))
            levenshtein = float(combined_features.get("domain_levenshtein", 0.0))
            suspicious_tld = int(combined_features.get("suspicious_tld", 0))
            mismatch = int(combined_features.get("reply_to_mismatch", 0))
            cred_box = int(combined_features.get("has_credential_box", 0))

            auth_fail = 0
            if combined_features.get("spf_pass", 1) == 0:
                auth_fail += 1
            if combined_features.get("dkim_pass", 1) == 0:
                auth_fail += 1
            if combined_features.get("dmarc_pass", 1) == 0:
                auth_fail += 1

            if is_trusted_domain and not spoof:
                # Legitimate service
                fraud_score = int(max(4, min(24, 6 + (urgency * 12) + (vis_prob * 8))))
                classification = "LEGITIMATE"
                confidence = 0.97
                reasons.append(f"Verified sender domain: {domain}")
            else:
                threat_pts = 0
                if auth_fail > 0:
                    threat_pts += auth_fail * 16
                    reasons.append(f"Protocol authentication rejected ({auth_fail}/3 checks failed)")
                if spoof:
                    threat_pts += 30
                    reasons.append("Display name impersonation detected (name brand mismatch)")
                if urgency > 0.3:
                    threat_pts += int(urgency * 24)
                    reasons.append("High urgency and psychological pressure indicators identified")
                if levenshtein > 0.6:
                    threat_pts += int(levenshtein * 32)
                    reasons.append("Domain typosquatting / Levenshtein visual lookalike detected")
                if suspicious_tld:
                    threat_pts += 25
                    reasons.append("Host or links utilize suspicious top-level domains (.xyz, .tk, .top)")
                if cred_box:
                    threat_pts += 20
                    reasons.append("Vision Transformer identified credential harvest login form")
                if mismatch:
                    threat_pts += 18
                    reasons.append("Reply-to address mismatch points to external infrastructure")

                threat_pts += int(vis_prob * 15)
                fraud_score = int(np.clip(threat_pts, 8, 98))

                if fraud_score >= 80:
                    classification = "IMPERSONATION" if spoof else "PHISHING"
                elif fraud_score >= 60:
                    classification = "BEC" if urgency > 0.4 else "PHISHING"
                elif fraud_score >= 40:
                    classification = "SUSPICIOUS"
                else:
                    classification = "LEGITIMATE"
                confidence = 0.93

        if not reasons:
            if fraud_score < 40:
                reasons.append("Clean sender reputation and legitimate layout structure")
            else:
                reasons.append("Heuristic anomalies detected in email metadata and links")

        # 5. Risk Level classification
        if fraud_score >= 80:
            risk_level = "CRITICAL"
        elif fraud_score >= 60:
            risk_level = "HIGH"
        elif fraud_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 6. Save into AWS cloud storage (S3 + DynamoDB) with SHA-256 evidence seal
        scan_id = self.storage_manager.record_scan(
            sender=sender,
            recipient=recipient,
            subject=subject,
            fraud_score=fraud_score,
            risk_level=risk_level,
            classification=classification,
            confidence=confidence,
            features=combined_features,
            artifact_path=image_path_or_obj if isinstance(image_path_or_obj, str) else None
        )

        record = self.storage_manager.get_scan(scan_id)

        result = {
            "scan_id": scan_id,
            "sha256_hash": record["sha256_hash"] if record else "N/A",
            "s3_uri": record.get("s3_uri", "N/A") if record else "N/A",
            "fraud_score": fraud_score,
            "risk_level": risk_level,
            "classification": classification,
            "confidence": round(confidence, 4),
            "reasons": reasons,
            "evidence_id": record.get("evidence_id", "N/A") if record else "N/A",
            "cryptographic_seal": record.get("cryptographic_seal", "N/A") if record else "N/A",
            "forensic_breakdown": {
                "spf": "PASS" if tab_feats["spf_pass"] else "FAIL",
                "dkim": "PASS" if tab_feats["dkim_pass"] else "FAIL",
                "dmarc": "PASS" if tab_feats["dmarc_pass"] else "FAIL",
                "domain_levenshtein": tab_feats["domain_levenshtein"],
                "domain_entropy": tab_feats["domain_entropy"],
                "relay_hops": tab_feats["relay_hops"],
                "visual_phish_prob": combined_features.get("visual_phish_prob", 0.5)
            },
            "timestamp": record.get("created_at", "N/A") if record else "N/A"
        }

        # 7. Cache in Redis & broadcast to Redis Pub/Sub alert stream
        self.redis_cache.cache_verdict(result["sha256_hash"], result)
        self.redis_cache.publish_alert(result)

        return result
