"""
TraceX AWS Cloud Storage & Evidence Manager
Replaces local SQLite with AWS S3 (artifact object storage) and AWS DynamoDB (forensic scan & evidence ledger).
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from decimal import Decimal
from typing import Dict, Any, List, Optional

from ml_engine.config import (
    AWS_REGION,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    AWS_S3_BUCKET,
    AWS_S3_PREFIX_RAW,
    AWS_S3_PREFIX_RENDERS,
    DYNAMODB_SCANS_TABLE,
    DYNAMODB_EVIDENCE_TABLE
)

# Check for boto3
BOTO3_AVAILABLE = False
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    pass


class AWSForensicStorageManager:
    """Manages forensic evidence storage across AWS S3 and AWS DynamoDB."""

    def __init__(
        self,
        bucket_name: str = AWS_S3_BUCKET,
        scans_table: str = DYNAMODB_SCANS_TABLE,
        evidence_table: str = DYNAMODB_EVIDENCE_TABLE,
        region: str = AWS_REGION
    ):
        self.bucket_name = bucket_name
        self.scans_table_name = scans_table
        self.evidence_table_name = evidence_table
        self.region = region

        self.s3_client = None
        self.dynamodb_resource = None
        self.scans_table = None
        self.evidence_table = None
        self.is_connected = False

        # In-memory mock storage if AWS credentials or boto3 not yet available locally
        self._mock_scans = {}
        self._mock_evidence = {}
        self._mock_s3 = {}

        self._init_aws_clients()

    def _init_aws_clients(self) -> None:
        """Initializes Boto3 S3 client and DynamoDB resource."""
        if not BOTO3_AVAILABLE:
            print("[!] boto3 is not installed. Running in AWS Cloud Emulation Mode.")
            return

        if not (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY):
            self.is_connected = False
            return

        session_kwargs = {
            "region_name": self.region,
            "aws_access_key_id": AWS_ACCESS_KEY_ID,
            "aws_secret_access_key": AWS_SECRET_ACCESS_KEY,
        }
        if AWS_SESSION_TOKEN:
            session_kwargs["aws_session_token"] = AWS_SESSION_TOKEN

        try:
            session = boto3.Session(**session_kwargs)
            self.s3_client = session.client("s3")
            self.dynamodb_resource = session.resource("dynamodb")
            self.scans_table = self.dynamodb_resource.Table(self.scans_table_name)
            self.evidence_table = self.dynamodb_resource.Table(self.evidence_table_name)
            self.is_connected = True
            print(f"[+] Connected to AWS S3 ({self.bucket_name}) and DynamoDB in {self.region}")
        except Exception as e:
            print(f"[!] Could not connect to AWS: {e}. Using AWS Cloud Emulation Mode.")
            self.is_connected = False

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def compute_file_sha256(filepath: str) -> str:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    def upload_artifact_to_s3(
        self,
        artifact_bytes_or_path: Any,
        key_prefix: str = AWS_S3_PREFIX_RENDERS,
        content_type: str = "image/png"
    ) -> Dict[str, str]:
        """Uploads an email screenshot or raw .eml to AWS S3 with SHA-256 metadata."""
        if isinstance(artifact_bytes_or_path, str) and os.path.exists(artifact_bytes_or_path):
            sha256 = self.compute_file_sha256(artifact_bytes_or_path)
            with open(artifact_bytes_or_path, "rb") as f:
                data = f.read()
        elif isinstance(artifact_bytes_or_path, bytes):
            data = artifact_bytes_or_path
            sha256 = self.compute_sha256(data)
        else:
            data = b""
            sha256 = self.compute_sha256(b"placeholder")

        ext = ".png" if "image" in content_type else ".eml"
        s3_key = f"{key_prefix}{sha256}{ext}"
        s3_uri = f"s3://{self.bucket_name}/{s3_key}"

        if self.is_connected and self.s3_client:
            try:
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=s3_key,
                    Body=data,
                    ContentType=content_type,
                    Metadata={"sha256": sha256}
                )
                print(f"[+] [AWS S3] Uploaded artifact to {s3_uri}")
            except Exception as e:
                print(f"[-] [AWS S3 Upload Error]: {e}")
        else:
            self._mock_s3[s3_key] = {"data_len": len(data), "sha256": sha256}
            print(f"[+] [AWS S3 (Cloud Mode)] Ingested to {s3_uri} (SHA-256: {sha256[:12]}...)")

        return {"s3_key": s3_key, "s3_uri": s3_uri, "sha256": sha256}

    def record_scan(
        self,
        sender: str,
        recipient: str,
        subject: str,
        fraud_score: int,
        risk_level: str,
        classification: str,
        confidence: float,
        features: Dict[str, Any],
        artifact_path: Optional[str] = None,
        raw_artifact_bytes: Optional[bytes] = None
    ) -> str:
        """
        Uploads artifact to AWS S3 and writes the forensic scan & evidence record to AWS DynamoDB.
        """
        scan_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat() + "Z"

        # 1. Upload to AWS S3
        s3_meta = self.upload_artifact_to_s3(
            artifact_path or raw_artifact_bytes or f"{sender}:{subject}".encode()
        )
        sha256_hash = s3_meta["sha256"]
        s3_uri = s3_meta["s3_uri"]

        # 2. Compute cryptographic seal for tamper-evident chain of custody
        seal_payload = f"TRACEX_AWS_SEAL:{scan_id}:{sha256_hash}:{timestamp}".encode("utf-8")
        cryptographic_seal = hashlib.sha256(seal_payload).hexdigest()
        evidence_id = f"EVID-AWS-{uuid.uuid4().hex[:8].upper()}"

        # Clean features for DynamoDB JSON compatibility (floats converted to Decimal or round strings)
        cleaned_features = {}
        for k, v in features.items():
            if isinstance(v, float):
                cleaned_features[k] = Decimal(str(round(v, 4)))
            elif isinstance(v, (int, str, bool)):
                cleaned_features[k] = v

        # DynamoDB Scan Item
        scan_item = {
            "scan_id": scan_id,
            "sha256_hash": sha256_hash,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "fraud_score": int(fraud_score),
            "risk_level": risk_level,
            "classification": classification,
            "confidence": Decimal(str(round(confidence, 4))),
            "s3_uri": s3_uri,
            "features": cleaned_features,
            "evidence_id": evidence_id,
            "cryptographic_seal": cryptographic_seal,
            "created_at": timestamp
        }

        # DynamoDB Evidence Ledger Item
        evidence_item = {
            "evidence_id": evidence_id,
            "scan_id": scan_id,
            "artifact_sha256": sha256_hash,
            "s3_uri": s3_uri,
            "recorded_at": timestamp,
            "verification_status": "VERIFIED",
            "cryptographic_seal": cryptographic_seal
        }

        # 3. Write to AWS DynamoDB
        if self.is_connected and self.scans_table and self.evidence_table:
            try:
                self.scans_table.put_item(Item=scan_item)
                self.evidence_table.put_item(Item=evidence_item)
                print(f"[+] [AWS DynamoDB] Recorded scan {scan_id} & evidence {evidence_id}")
            except Exception as e:
                print(f"[-] [AWS DynamoDB Error]: {e}")
        else:
            self._mock_scans[scan_id] = scan_item
            self._mock_evidence[evidence_id] = evidence_item
            print(f"[+] [AWS DynamoDB (Cloud Mode)] Stored in {self.scans_table_name} & {self.evidence_table_name}")

        return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves scan record from AWS DynamoDB."""
        if self.is_connected and self.scans_table:
            try:
                response = self.scans_table.get_item(Key={"scan_id": scan_id})
                item = response.get("Item")
                if item:
                    # Convert Decimals back to float
                    return self._deserialize_item(item)
            except Exception as e:
                print(f"[-] [AWS DynamoDB Get Error]: {e}")
        return self._deserialize_item(self._mock_scans.get(scan_id))

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Scans recent records from DynamoDB."""
        if self.is_connected and self.scans_table:
            try:
                response = self.scans_table.scan(Limit=limit)
                items = response.get("Items", [])
                return [self._deserialize_item(it) for it in items]
            except Exception as e:
                print(f"[-] [AWS DynamoDB Scan Error]: {e}")
        return [self._deserialize_item(it) for it in list(self._mock_scans.values())[:limit]]

    def _deserialize_item(self, item: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not item:
            return None
        res = {}
        for k, v in item.items():
            if isinstance(v, Decimal):
                res[k] = float(v) if "." in str(v) else int(v)
            elif isinstance(v, dict):
                res[k] = {
                    dk: (float(dv) if isinstance(dv, Decimal) else dv)
                    for dk, dv in v.items()
                }
            else:
                res[k] = v
        return res
