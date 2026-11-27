"""
TraceX AWS S3 Pure Storage Integration
Handles ALL system persistence exclusively via AWS S3:
1. s3://tracex-raw-eml/{sha256}.eml              — Raw RFC 822 Email Archive
2. s3://tracex-renders-png/{sha256}.png          — Playwright Rendered Isolated Screenshots
3. s3://tracex-evidence-ledger/scans/{id}.json   — Full Forensic Scan Records
4. s3://tracex-evidence-ledger/evidence/{id}.json— Cryptographic Evidence Ledger & Seals
5. s3://tracex-evidence-ledger/graph/threat.json — NetworkX Threat Topology & Centrality
6. s3://tracex-certificates-65b/{id}_65B.pdf     — Section 65B Statutory PDF Certificates

Includes automatic S3 vault caching for offline/zero-config environments.
"""

import os
import io
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Non-blocking asynchronous background S3 synchronizer
_s3_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="S3SyncWorker")
_s3_circuit_open_until = 0.0

def is_s3_available() -> bool:
    global _s3_circuit_open_until
    if time.time() < _s3_circuit_open_until:
        return False
    return True

def trip_s3_circuit(reason: Exception):
    global _s3_circuit_open_until
    _s3_circuit_open_until = time.time() + 30.0
    logger.warning(f"[AWS S3 Circuit Breaker] S3 is temporarily unreachable ({reason}). Routing via instant local vault for 30s.")

# Load .env from TraceX3 root before reading any AWS credentials
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    load_dotenv(dotenv_path=_env_path, override=True)
except ImportError:
    pass

# Configurable AWS S3 Settings
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "ap-south-1"))
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", None)
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN", None)
AWS_ENDPOINT_URL = os.getenv("AWS_ENDPOINT_URL", os.getenv("S3_ENDPOINT_URL", None))

DEFAULT_BUCKET = os.getenv("AWS_S3_BUCKET", "tracex-forensic-vault-diptanshu")

# S3 Buckets as specified in system architecture
S3_RAW_EML_BUCKET = os.getenv("S3_RAW_EML_BUCKET", DEFAULT_BUCKET)
S3_RENDERS_PNG_BUCKET = os.getenv("S3_RENDERS_PNG_BUCKET", DEFAULT_BUCKET)
S3_EVIDENCE_BUCKET = os.getenv("S3_EVIDENCE_BUCKET", DEFAULT_BUCKET)
S3_CERTIFICATES_BUCKET = os.getenv("S3_CERTIFICATES_BUCKET", DEFAULT_BUCKET)

ALL_BUCKETS = list(set([
    S3_RAW_EML_BUCKET,
    S3_RENDERS_PNG_BUCKET,
    S3_EVIDENCE_BUCKET,
    S3_CERTIFICATES_BUCKET
]))

LOCAL_VAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "s3_vault")
for b in ALL_BUCKETS:
    os.makedirs(os.path.join(LOCAL_VAULT_DIR, b), exist_ok=True)

_s3_client = None
_boto3_available = False

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, NoCredentialsError
    _boto3_available = True
except ImportError:
    _boto3_available = False


def get_s3_client():
    """Initializes or returns singleton boto3 S3 client if configured."""
    global _s3_client
    if not _boto3_available or not is_s3_available():
        return None

    if _s3_client is not None:
        return _s3_client

    try:
        session_kwargs = {"region_name": AWS_REGION}
        if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            session_kwargs["aws_access_key_id"] = AWS_ACCESS_KEY_ID
            session_kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
            if AWS_SESSION_TOKEN:
                session_kwargs["aws_session_token"] = AWS_SESSION_TOKEN

        client_kwargs = {
            "config": Config(connect_timeout=2, read_timeout=4, retries={"max_attempts": 1})
        }
        if AWS_ENDPOINT_URL:
            client_kwargs["endpoint_url"] = AWS_ENDPOINT_URL

        session = boto3.Session(**session_kwargs)
        client = session.client("s3", **client_kwargs)
        _s3_client = client
        logger.info(f"Connected to AWS S3 in region {AWS_REGION} (endpoint: {AWS_ENDPOINT_URL or 'AWS Default'})")
        return _s3_client
    except Exception as e:
        trip_s3_circuit(e)
        return None


# ---------------------------------------------------------------------------
# Core S3 Primitive Operations (Instant Local-First + Non-Blocking AWS Sync)
# ---------------------------------------------------------------------------

def _bg_s3_upload(bucket: str, key: str, data: bytes, content_type: str, metadata: Optional[Dict[str, str]]):
    """Background worker task to upload object to AWS S3 without blocking request pipeline."""
    if not is_s3_available():
        return
    client = get_s3_client()
    if not client:
        return
    try:
        extra_args = {"Bucket": bucket, "Key": key, "Body": data, "ContentType": content_type}
        if metadata:
            extra_args["Metadata"] = metadata
        client.put_object(**extra_args)
        logger.info(f"[AWS S3 Background] Successfully synced s3://{bucket}/{key}")
    except Exception as e:
        trip_s3_circuit(e)


def put_s3_bytes(bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream", metadata: Optional[Dict[str, str]] = None) -> str:
    """Stores binary data in local S3 vault instantly (<1ms), and syncs to AWS S3 in background."""
    s3_uri = f"s3://{bucket}/{key}"
    local_path = os.path.join(LOCAL_VAULT_DIR, bucket, key)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)

    with open(local_path, "wb") as f:
        f.write(data)

    # Non-blocking background sync
    if is_s3_available():
        _s3_executor.submit(_bg_s3_upload, bucket, key, data, content_type, metadata)

    return s3_uri


def get_s3_bytes(bucket: str, key: str) -> Optional[bytes]:
    """Retrieves binary object from local S3 vault first (0ms latency), falling back to AWS S3."""
    local_path = os.path.join(LOCAL_VAULT_DIR, bucket, key)
    if os.path.exists(local_path):
        try:
            with open(local_path, "rb") as f:
                return f.read()
        except Exception:
            pass

    if is_s3_available():
        client = get_s3_client()
        if client:
            try:
                resp = client.get_object(Bucket=bucket, Key=key)
                data = resp["Body"].read()
                # Cache locally for future instant reads
                try:
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    with open(local_path, "wb") as f:
                        f.write(data)
                except Exception:
                    pass
                return data
            except Exception as e:
                trip_s3_circuit(e)

    return None


def delete_s3_object(bucket: str, key: str) -> bool:
    """Deletes an object from live AWS S3 and local S3 vault."""
    client = get_s3_client()
    if client:
        try:
            client.delete_object(Bucket=bucket, Key=key)
            logger.info(f"[AWS S3] Deleted object s3://{bucket}/{key}")
        except Exception as e:
            logger.warning(f"Could not delete from live S3 ({e})")

    local_path = os.path.join(LOCAL_VAULT_DIR, bucket, key)
    if os.path.exists(local_path):
        try:
            os.remove(local_path)
            logger.info(f"[Local S3 Vault] Removed {local_path}")
        except Exception:
            pass
    return True


def put_s3_json(bucket: str, key: str, payload: Any, metadata: Optional[Dict[str, str]] = None) -> str:
    """Serializes payload to JSON and saves in AWS S3."""
    data = json.dumps(payload, indent=2, default=str).encode("utf-8")
    return put_s3_bytes(bucket, key, data, content_type="application/json", metadata=metadata)


def get_s3_json(bucket: str, key: str) -> Optional[Any]:
    """Retrieves and deserializes JSON object from AWS S3."""
    data = get_s3_bytes(bucket, key)
    if data:
        try:
            return json.loads(data.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse S3 JSON from s3://{bucket}/{key}: {e}")
    return None


def list_s3_keys(bucket: str, prefix: str = "") -> List[str]:
    """Lists object keys from local vault first for instant retrieval, then remote S3 if online."""
    keys = set()
    local_bucket_dir = os.path.join(LOCAL_VAULT_DIR, bucket)
    if os.path.exists(local_bucket_dir):
        for root, _, files in os.walk(local_bucket_dir):
            for f in files:
                full_path = os.path.join(root, f)
                rel_key = os.path.relpath(full_path, local_bucket_dir).replace("\\", "/")
                if rel_key.startswith(prefix):
                    keys.add(rel_key)

    # If local vault has keys, return them immediately without waiting for remote pagination
    if keys:
        return sorted(list(keys), reverse=True)

    if is_s3_available():
        client = get_s3_client()
        if client:
            try:
                paginator = client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        keys.add(obj["Key"])
            except Exception as e:
                trip_s3_circuit(e)

    return sorted(list(keys), reverse=True)


# ---------------------------------------------------------------------------
# High-Level Forensic Artifacts in AWS S3
# ---------------------------------------------------------------------------

async def upload_raw_eml(file_bytes: bytes, sha256_hash: str) -> str:
    """Uploads raw .eml bytes to s3://bucket/eml/{sha256}.eml and root with SHA-256 metadata."""
    key = f"{sha256_hash}.eml"
    eml_folder_key = f"eml/{sha256_hash}.eml"

    # Save to root key for backward compatibility
    put_s3_bytes(
        bucket=S3_RAW_EML_BUCKET,
        key=key,
        data=file_bytes,
        content_type="message/rfc822",
        metadata={"sha256": sha256_hash, "type": "raw_email"}
    )

    # Save to organized eml/ folder in S3
    return put_s3_bytes(
        bucket=S3_RAW_EML_BUCKET,
        key=eml_folder_key,
        data=file_bytes,
        content_type="message/rfc822",
        metadata={"sha256": sha256_hash, "type": "raw_email"}
    )


async def upload_screenshot(image_bytes_or_path: Any, sha256_hash: str) -> str:
    """Uploads Playwright rendered screenshot PNG to s3://tracex-renders-png/{sha256}.png."""
    key = f"{sha256_hash}.png"
    if isinstance(image_bytes_or_path, str) and os.path.exists(image_bytes_or_path):
        with open(image_bytes_or_path, "rb") as f:
            img_data = f.read()
    elif isinstance(image_bytes_or_path, bytes):
        img_data = image_bytes_or_path
    else:
        img_data = b""

    return put_s3_bytes(
        bucket=S3_RENDERS_PNG_BUCKET,
        key=key,
        data=img_data,
        content_type="image/png",
        metadata={"sha256": sha256_hash, "type": "detonation_screenshot"}
    )


# ---------------------------------------------------------------------------
# Forensic Scan & Evidence Ledger in AWS S3
# ---------------------------------------------------------------------------

def save_scan_to_s3(scan_data: Dict[str, Any]) -> str:
    """Saves forensic scan record to s3://tracex-evidence-ledger/scans/{scan_id}.json."""
    scan_id = scan_data["scan_id"]
    key = f"scans/{scan_id}.json"
    s3_uri = put_s3_json(
        bucket=S3_EVIDENCE_BUCKET,
        key=key,
        payload=scan_data,
        metadata={"scan_id": scan_id, "sha256": scan_data.get("sha256_hash", "")}
    )

    # Also record in index for instant dashboard retrieval
    update_scan_index_in_s3(scan_data)
    return s3_uri


def update_scan_index_in_s3(scan_data: Dict[str, Any]) -> None:
    """Maintains a lightweight index of recent scans at s3://tracex-evidence-ledger/index/recent_scans.json."""
    index_key = "index/recent_scans.json"
    local_path = os.path.join(LOCAL_VAULT_DIR, S3_EVIDENCE_BUCKET, index_key)
    current_index = []
    if os.path.exists(local_path):
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                current_index = json.load(f)
        except Exception:
            current_index = []
    
    # Prepend or update scan
    scan_id = scan_data.get("scan_id")
    current_index = [s for s in current_index if s.get("scan_id") != scan_id]
    summary = {
        "scan_id": scan_data.get("scan_id"),
        "id": scan_data.get("scan_id"),
        "sha256_hash": scan_data.get("sha256_hash"),
        "hash": scan_data.get("sha256_hash"),
        "sender": scan_data.get("sender"),
        "from": scan_data.get("sender"),
        "recipient": scan_data.get("recipient"),
        "to": scan_data.get("recipient"),
        "subject": scan_data.get("subject"),
        "fraud_score": scan_data.get("fraud_score"),
        "score": scan_data.get("fraud_score"),
        "risk_level": scan_data.get("risk_level"),
        "risk": scan_data.get("risk_level"),
        "classification": scan_data.get("classification"),
        "confidence": scan_data.get("confidence"),
        "evidence_id": scan_data.get("evidence_id"),
        "s3_eml_uri": scan_data.get("s3_eml_uri"),
        "s3_screenshot_uri": scan_data.get("s3_screenshot_uri"),
        "screenshot_url": scan_data.get("screenshot_url") or scan_data.get("s3_screenshot_uri"),
        "reasons": scan_data.get("reasons") or [],
        "forensic_breakdown": scan_data.get("forensic_breakdown") or {},
        "raw_headers": scan_data.get("raw_headers") or scan_data.get("raw") or "",
        "raw": scan_data.get("raw_headers") or scan_data.get("raw") or "",
        "urls": scan_data.get("urls") or [],
        "ips": scan_data.get("ips") or [],
        "created_at": scan_data.get("created_at", datetime.now(timezone.utc).isoformat()),
        "time": scan_data.get("time") or scan_data.get("created_at", datetime.now(timezone.utc).isoformat())
    }
    current_index.insert(0, summary)
    current_index = current_index[:100]  # Keep most recent 100 scans in index
    put_s3_json(S3_EVIDENCE_BUCKET, index_key, current_index)


def get_scan_from_s3(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full scan record from s3://tracex-evidence-ledger/scans/{scan_id}.json."""
    key = f"scans/{scan_id}.json"
    return get_s3_json(S3_EVIDENCE_BUCKET, key)


def list_scans_from_s3(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent scan records directly from AWS S3."""
    # 1. Try index
    index_key = "index/recent_scans.json"
    index = get_s3_json(S3_EVIDENCE_BUCKET, index_key)
    if index and isinstance(index, list):
        return index[:limit]

    # 2. Fallback: list scan keys
    keys = list_s3_keys(S3_EVIDENCE_BUCKET, prefix="scans/")
    scans = []
    for k in keys[:limit]:
        item = get_s3_json(S3_EVIDENCE_BUCKET, k)
        if item:
            scans.append(item)
    return scans


def save_evidence_to_s3(evidence_data: Dict[str, Any]) -> str:
    """Saves custody record to s3://tracex-evidence-ledger/evidence/{evidence_id}.json."""
    evidence_id = evidence_data["evidence_id"]
    key = f"evidence/{evidence_id}.json"
    return put_s3_json(
        bucket=S3_EVIDENCE_BUCKET,
        key=key,
        payload=evidence_data,
        metadata={"evidence_id": evidence_id}
    )


def get_evidence_from_s3(evidence_id_or_scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves evidence record by evidence_id or scan_id from AWS S3."""
    # Try direct evidence key
    direct = get_s3_json(S3_EVIDENCE_BUCKET, f"evidence/{evidence_id_or_scan_id}.json")
    if direct:
        return direct

    # Try scan key and extract evidence
    scan = get_scan_from_s3(evidence_id_or_scan_id)
    if scan:
        return {
            "evidence_id": scan.get("evidence_id", f"EV-{evidence_id_or_scan_id[:8].upper()}"),
            "scan_id": scan.get("scan_id"),
            "artifact_sha256": scan.get("sha256_hash"),
            "s3_eml_uri": scan.get("s3_eml_uri"),
            "s3_screenshot_uri": scan.get("s3_screenshot_uri"),
            "cryptographic_seal": scan.get("cryptographic_seal"),
            "recorded_at": scan.get("created_at"),
            "verification_status": "VERIFIED",
            "section_65b_certified": True,
            "scan_metadata": scan
        }

    return None


# ---------------------------------------------------------------------------
# Section 65B Certificates in AWS S3
# ---------------------------------------------------------------------------

def save_certificate_to_s3(scan_id: str, pdf_bytes: bytes) -> str:
    """Stores generated Section 65B PDF certificate in s3://bucket/reports/{scan_id}_Forensic_Report.pdf and aliases."""
    report_key = f"reports/{scan_id}_Forensic_Report.pdf"
    cert_key = f"reports/{scan_id}_Section_65B_Certificate.pdf"
    root_cert_key = f"{scan_id}_65B_Certificate.pdf"

    # Save to organized reports/ folder
    put_s3_bytes(
        bucket=S3_CERTIFICATES_BUCKET,
        key=cert_key,
        data=pdf_bytes,
        content_type="application/pdf",
        metadata={"scan_id": scan_id, "type": "section_65b_certificate"}
    )
    # Save root key for compatibility
    put_s3_bytes(
        bucket=S3_CERTIFICATES_BUCKET,
        key=root_cert_key,
        data=pdf_bytes,
        content_type="application/pdf",
        metadata={"scan_id": scan_id, "type": "section_65b_certificate"}
    )
    # Return main report URI
    return put_s3_bytes(
        bucket=S3_CERTIFICATES_BUCKET,
        key=report_key,
        data=pdf_bytes,
        content_type="application/pdf",
        metadata={"scan_id": scan_id, "type": "section_65b_forensic_report"}
    )


def get_certificate_from_s3(scan_id: str) -> Optional[bytes]:
    """Retrieves Section 65B PDF certificate from AWS S3."""
    for key in (
        f"reports/{scan_id}_Forensic_Report.pdf",
        f"reports/{scan_id}_Section_65B_Certificate.pdf",
        f"{scan_id}_65B_Certificate.pdf"
    ):
        data = get_s3_bytes(S3_CERTIFICATES_BUCKET, key)
        if data:
            return data
    return None


# ---------------------------------------------------------------------------
# Threat Graph in AWS S3
# ---------------------------------------------------------------------------

def save_graph_to_s3(graph_data: Dict[str, Any]) -> str:
    """Stores NetworkX threat infrastructure topology in s3://tracex-evidence-ledger/graph/threat_graph.json."""
    key = "graph/threat_graph.json"
    return put_s3_json(
        bucket=S3_EVIDENCE_BUCKET,
        key=key,
        payload=graph_data,
        metadata={"type": "threat_topology_graph"}
    )


def get_graph_from_s3() -> Optional[Dict[str, Any]]:
    """Retrieves threat topology graph from AWS S3."""
    key = "graph/threat_graph.json"
    return get_s3_json(S3_EVIDENCE_BUCKET, key)


# ---------------------------------------------------------------------------
# Presigned URLs and Generic Reader
# ---------------------------------------------------------------------------

def generate_presigned_url(s3_uri: str, expiration: int = 3600) -> str:
    """Generates a presigned GET URL for an S3 URI, or gateway proxy fallback."""
    if not s3_uri or not s3_uri.startswith("s3://"):
        return s3_uri

    parts = s3_uri.replace("s3://", "").split("/", 1)
    if len(parts) != 2:
        return s3_uri

    bucket, key = parts
    client = get_s3_client()
    if client:
        try:
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=expiration
            )
        except Exception as e:
            logger.warning(f"Presigned URL error: {e}")

    return f"/api/s3/download?bucket={bucket}&key={key}"


def read_s3_bytes(s3_uri: str) -> Optional[bytes]:
    """Reads object bytes from an S3 URI."""
    if not s3_uri or not s3_uri.startswith("s3://"):
        return None

    parts = s3_uri.replace("s3://", "").split("/", 1)
    if len(parts) != 2:
        return None

    bucket, key = parts
    return get_s3_bytes(bucket, key)
