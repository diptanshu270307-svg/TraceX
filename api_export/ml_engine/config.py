"""
TraceX Configuration & Cloud Settings
Manages AWS cloud credentials, S3 buckets, DynamoDB tables, and ML thresholds.
"""

import os

# AWS Cloud Settings
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "ap-south-1"))
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", None)
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN", None)

# S3 Buckets
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "tracex-forensic-vault")
AWS_S3_PREFIX_RAW = "raw-emails/"
AWS_S3_PREFIX_RENDERS = "rendered-screenshots/"
AWS_S3_PREFIX_REPORTS = "forensic-reports/"

# DynamoDB Tables
DYNAMODB_SCANS_TABLE = os.getenv("DYNAMODB_SCANS_TABLE", "TraceX_Scans")
DYNAMODB_EVIDENCE_TABLE = os.getenv("DYNAMODB_EVIDENCE_TABLE", "TraceX_EvidenceLedger")

# Redis In-Memory Cache & Pub/Sub
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_URL = os.getenv("REDIS_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")

# ML Engine Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models", "saved_models")
