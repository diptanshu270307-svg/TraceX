"""
TraceX AWS Infrastructure Provisioning Script
Automatically creates the AWS S3 Bucket and AWS DynamoDB tables with one command.
"""

import os
import sys

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
project_root = os.path.dirname(base_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ml_engine.config import (
    AWS_REGION,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_S3_BUCKET,
    DYNAMODB_SCANS_TABLE,
    DYNAMODB_EVIDENCE_TABLE
)

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


def provision_aws_infrastructure():
    print("=" * 70)
    print("  TRACEX AWS CLOUD INFRASTRUCTURE PROVISIONER")
    print(f"  Region: {AWS_REGION} | Bucket: {AWS_S3_BUCKET}")
    print("=" * 70)

    if not BOTO3_AVAILABLE:
        print("[-] boto3 is not installed. Please run: pip install boto3")
        return

    session = boto3.Session(
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    s3 = session.client("s3")
    dynamodb = session.client("dynamodb")

    # 1. Provision S3 Bucket
    print(f"\n[*] Provisioning S3 Bucket: {AWS_S3_BUCKET}...")
    try:
        if AWS_REGION == "us-east-1":
            s3.create_bucket(Bucket=AWS_S3_BUCKET)
        else:
            s3.create_bucket(
                Bucket=AWS_S3_BUCKET,
                CreateBucketConfiguration={"LocationConstraint": AWS_REGION}
            )
        print(f"[+] S3 Bucket '{AWS_S3_BUCKET}' created successfully.")
    except ClientError as e:
        if e.response["Error"]["Code"] in ["BucketAlreadyOwnedByYou", "BucketAlreadyExists"]:
            print(f"[+] S3 Bucket '{AWS_S3_BUCKET}' already exists.")
        else:
            print(f"[-] S3 Bucket creation warning: {e}")

    # 2. Enable S3 Default Encryption
    try:
        s3.put_bucket_encryption(
            Bucket=AWS_S3_BUCKET,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        )
        print(f"[+] S3 Server-side AES256 Encryption enabled.")
    except Exception as e:
        print(f"[!] S3 encryption note: {e}")

    # 3. Provision DynamoDB Scans Table
    print(f"\n[*] Provisioning DynamoDB Table: {DYNAMODB_SCANS_TABLE}...")
    try:
        dynamodb.create_table(
            TableName=DYNAMODB_SCANS_TABLE,
            KeySchema=[
                {"AttributeName": "scan_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "scan_id", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST" # Serverless on-demand pricing
        )
        print(f"[+] DynamoDB Table '{DYNAMODB_SCANS_TABLE}' created.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            print(f"[+] DynamoDB Table '{DYNAMODB_SCANS_TABLE}' already exists.")
        else:
            print(f"[-] DynamoDB creation error: {e}")

    # 4. Provision DynamoDB Evidence Ledger Table
    print(f"\n[*] Provisioning DynamoDB Table: {DYNAMODB_EVIDENCE_TABLE}...")
    try:
        dynamodb.create_table(
            TableName=DYNAMODB_EVIDENCE_TABLE,
            KeySchema=[
                {"AttributeName": "evidence_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "evidence_id", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST"
        )
        print(f"[+] DynamoDB Table '{DYNAMODB_EVIDENCE_TABLE}' created.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            print(f"[+] DynamoDB Table '{DYNAMODB_EVIDENCE_TABLE}' already exists.")
        else:
            print(f"[-] DynamoDB creation error: {e}")

    print("\n" + "=" * 70)
    print("  AWS INFRASTRUCTURE PROVISIONING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    provision_aws_infrastructure()
