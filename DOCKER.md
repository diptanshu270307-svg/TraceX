# TraceX Pure AWS S3 Docker Container Guide

TraceX is packaged as a lightweight, production-hardened container operating with **AWS S3 as its sole and exclusive storage engine** — eliminating databases (PostgreSQL, SQLite, DynamoDB) and local disk dependencies.

The single container bundles:
1. **SIH 26 Access Portal** (`/login`): Cyan/dark theme sliding login & registration system authenticated purely via AWS S3.
2. **TraceX Command Center Dashboard** (`/`): Real-time investigation, recent scans history, and Section 65B legal certificate downloads.
3. **TraceX Chrome Extension Backend** (`/investigate` & `/api/scan`): Intercepts threats in Gmail and automatically redirects analysts to `/login`.
4. **Forensic Pipeline**: Playwright isolated Chromium detonation sandbox + Donut ViT OCR-free feature extractor + XGBoost risk classification + NetworkX correlation.

---

## 1. Storage Architecture: Pure AWS S3

Every artifact, forensic scan record, custody seal, user profile, and legal certificate is persisted directly into dedicated AWS S3 buckets:

| Artifact Type | S3 Bucket URI | Format | Description |
| :--- | :--- | :--- | :--- |
| **User Profiles** | `s3://tracex-evidence-ledger/auth/users/{username}.json` | JSON | Salted SHA-256 password hash, role, and analyst identity |
| **Session Tokens**| `s3://tracex-evidence-ledger/auth/sessions/{token}.json` | JSON | 7-day cryptographic analyst session state |
| **Raw Email** | `s3://tracex-raw-eml/{sha256}.eml` | RFC 822 | Bit-for-bit immutable original email message |
| **Visual Render** | `s3://tracex-renders-png/{sha256}.png` | PNG | Isolated Playwright detonation sandbox screenshot |
| **Scan Metadata** | `s3://tracex-evidence-ledger/scans/{scan_id}.json` | JSON | Forensic breakdown, SPF/DKIM/DMARC flags, XGBoost scores |
| **Evidence Ledger** | `s3://tracex-evidence-ledger/evidence/{id}.json` | JSON | Tamper-evident custody records & cryptographic SHA-256 seals |
| **Threat Topology** | `s3://tracex-evidence-ledger/graph/threat_graph.json` | JSON | NetworkX threat graph, betweenness centrality, communities |
| **Section 65B Certificate** | `s3://tracex-certificates-65b/{id}_65B_Certificate.pdf` | PDF | Statutory Certificate under Indian Evidence Act §65B / BSA §63 |

---

## 2. Quick Start: Build & Run with Docker

### Option A: Standard Build & Run
```bash
# 1. Build the TraceX Docker Image
docker build -t tracex-threat-defense:latest .

# 2. Run with AWS S3 Credentials
docker run -d \
  --name tracex \
  -p 8000:8000 \
  -e AWS_REGION="ap-south-1" \
  -e AWS_ACCESS_KEY_ID="<YOUR_KEY>" \
  -e AWS_SECRET_ACCESS_KEY="<YOUR_SECRET>" \
  -e S3_RAW_EML_BUCKET="tracex-raw-eml" \
  -e S3_RENDERS_PNG_BUCKET="tracex-renders-png" \
  -e S3_EVIDENCE_BUCKET="tracex-evidence-ledger" \
  -e S3_CERTIFICATES_BUCKET="tracex-certificates-65b" \
  tracex-threat-defense:latest
```

### Option B: Docker Compose
```bash
# 1. Copy template and add your AWS credentials
cp .env.example .env

# 2. Launch container in detached mode
docker compose up -d

# 3. View live logs
docker compose logs -f tracex
```

### Option C: Offline Local S3 Emulation (No AWS Billing)
If you wish to test containerized S3 storage locally without live AWS credentials:
```bash
docker compose --profile local-s3 up -d
```
This boots a LocalStack S3 emulator on port `4566` alongside TraceX.

---

## 3. Container Verification & Endpoints

Once the container is running:
- **SIH 26 Login Portal**: `http://localhost:8000/login`
  - Default initial analyst: `admin` / `tracex2026!`
  - Or click **Register** to create a new profile persisted into AWS S3.
- **TraceX Command Center**: `http://localhost:8000/`
- **Recent Scans API**: `http://localhost:8000/api/scans` (Queries `s3://tracex-evidence-ledger/`)
- **Download Section 65B Certificate**: `http://localhost:8000/api/evidence/{id}` (Downloads PDF from `s3://tracex-certificates-65b/`)
- **Upload & Scan**: `POST http://localhost:8000/api/scan` (`multipart/form-data`)
- **Chrome Extension Redirect Target**: `GET http://localhost:8000/investigate?case_id={id}` (Redirects to `/login`)
- **Interactive Swagger Docs**: `http://localhost:8000/docs`

---

## 4. Loading the TraceX Chrome Extension

The renamed Chrome extension is located in [`extension/`](file:///c:/Users/Atul%20Changediya/Downloads/TraceX3/extension):
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked** and select the folder:
   `c:\Users\Atul Changediya\Downloads\TraceX3\extension`
4. The extension **"TraceX - Email Threat Sentinel"** is now active.
5. In Gmail, when suspicious emails appear, clicking **"TraceX: Escalate to Detonation Sandbox &rarr;"** redirects directly to `http://localhost:8000/login`, taking you seamlessly into the investigation dashboard upon authentication!

---

## 5. Cloud Deployment (AWS ECS / EKS / Fargate)

Because the container is completely stateless and relies purely on AWS S3, it is natively cloud-ready for AWS Elastic Container Service (ECS) and Kubernetes:

1. **Push to Amazon ECR**:
   ```bash
   aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com
   docker tag tracex-threat-defense:latest <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/tracex:latest
   docker push <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/tracex:latest
   ```

2. **IAM Task Execution Role**:
   Grant the ECS Task Role permissions for your S3 buckets:
   - `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on:
     - `arn:aws:s3:::tracex-raw-eml/*`
     - `arn:aws:s3:::tracex-renders-png/*`
     - `arn:aws:s3:::tracex-evidence-ledger/*`
     - `arn:aws:s3:::tracex-certificates-65b/*`
