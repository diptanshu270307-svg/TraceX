#!/usr/bin/env python3
"""
package_extension.py — Packages TraceX Chrome Extension and uploads to AWS S3.
"""
import os
import zipfile
import boto3
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

EXTENSION_DIR = os.path.join(BASE_DIR, "extension")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "gateway", "data", "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

ZIP_PATH = os.path.join(DOWNLOADS_DIR, "tracex-sentinel-extension.zip")

FILES_TO_INCLUDE = [
    "manifest.json",
    "background.js",
    "content.js",
    "styles.css",
    "config.js",
]

def package_extension():
    print(f"[*] Packaging Chrome Extension from {EXTENSION_DIR}...")
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in FILES_TO_INCLUDE:
            fpath = os.path.join(EXTENSION_DIR, fname)
            if os.path.exists(fpath):
                zf.write(fpath, arcname=fname)
                print(f"  + Added: {fname}")
            else:
                print(f"  ! Warning: {fname} not found in {EXTENSION_DIR}")
        
        # Include icons if present
        for item in os.listdir(EXTENSION_DIR):
            if item.endswith((".png", ".jpg", ".svg")) and item not in FILES_TO_INCLUDE:
                zf.write(os.path.join(EXTENSION_DIR, item), arcname=item)
                print(f"  + Added icon/asset: {item}")

    print(f"[+] Successfully created extension bundle: {ZIP_PATH} ({os.path.getsize(ZIP_PATH)} bytes)")
    return ZIP_PATH

def upload_to_s3(zip_path):
    bucket = os.getenv("AWS_S3_BUCKET", "tracex-forensic-vault-diptanshu")
    region = os.getenv("AWS_REGION", "ap-south-1")
    s3_key = "downloads/tracex-sentinel-extension.zip"

    print(f"[*] Uploading extension package to s3://{bucket}/{s3_key} in {region}...")
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=region
        )
        with open(zip_path, "rb") as f:
            s3.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=f.read(),
                ContentType="application/zip",
                Metadata={"platform": "Chrome", "version": "2.0"}
            )
        s3_url = f"https://{bucket}.s3.{region}.amazonaws.com/{s3_key}"
        print(f"[+] Extension package published successfully to AWS S3!")
        print(f"[+] S3 URI: s3://{bucket}/{s3_key}")
        print(f"[+] S3 HTTPS URL: {s3_url}")
        return s3_url
    except Exception as e:
        print(f"[-] S3 upload failed ({e}). Package remains preserved locally at {zip_path}")
        return None

if __name__ == "__main__":
    pkg = package_extension()
    upload_to_s3(pkg)
