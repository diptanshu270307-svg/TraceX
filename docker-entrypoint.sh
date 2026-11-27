#!/usr/bin/env bash
set -e

echo "======================================================================"
echo " TraceX Cyber-Forensic Threat Defense Platform (Docker Container)"
echo " Storage Backend: Pure AWS S3 (Raw EML, Screenshots, Evidence Ledger)"
echo "======================================================================"

# Display AWS S3 Configuration
echo "[*] AWS Region:               ${AWS_REGION:-ap-south-1}"
echo "[*] S3 Raw EML Bucket:        ${S3_RAW_EML_BUCKET:-tracex-raw-eml}"
echo "[*] S3 Renders PNG Bucket:    ${S3_RENDERS_PNG_BUCKET:-tracex-renders-png}"
echo "[*] S3 Evidence Ledger Bucket:${S3_EVIDENCE_BUCKET:-tracex-evidence-ledger}"
echo "[*] S3 Certificates Bucket:   ${S3_CERTIFICATES_BUCKET:-tracex-certificates-65b}"

if [ -n "$AWS_ENDPOINT_URL" ]; then
    echo "[*] Custom S3 Endpoint:       ${AWS_ENDPOINT_URL}"
fi

if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "[!] Notice: AWS credentials not provided in environment."
    echo "[!] Container operating with resilient local S3 vault cache."
else
    echo "[+] AWS S3 credentials detected."
fi

# Ensure data directory permissions
mkdir -p /app/gateway/data/s3_vault

# Run the passed command (e.g. uvicorn gateway.main:app)
exec "$@"
