# TraceX — Cyber-Forensic Email Threat Defense & Digital Trust Platform

> Built by **Team Kajukatli (`CAN-TEAM-001461`)** for **Code-A-Nova — Cybersecurity & Digital Trust Track**

**TraceX** is an end-to-end cyber-forensic email threat intelligence, real-time phishing detection, threat infrastructure graph correlation, and court-admissible **Section 65B (Indian Evidence Act / BSA §63)** digital evidence preservation platform.

---

## Key Features

- **Real-Time `.eml` Forensic Ingestion & Analysis (`/api/scan`)**
  - Computes immediate SHA-256 cryptographic hashes for tamper-evident custody.
  - Parses RFC 822 headers (`SPF`, `DKIM`, `DMARC`, relay hops, embedded URLs, originating IPs).
  - Runs deterministic protocol + brand-impersonation + urgency/TLD heuristics alongside multimodal **XGBoost** & visual detonation rendering (Playwright Chromium with high-fidelity Pillow fallback).
- **NetworkX Threat Infrastructure Topology (`/api/graph`)**
  - Correlates senders, domains, IPs, and campaigns into an interactive threat graph with betweenness centrality and Louvain community detection.
- **Court-Admissible Section 65B / BSA §63 Certificate Generator (`/api/evidence/{id}`)**
  - Auto-generates downloadable, cryptographically sealed PDF certificates and RFC 822 `.eml` evidence exports via ReportLab.
- **S3-Native Cloud Persistence with Resilient Local Vault Fallback**
  - Stores raw emails, visual captures, evidence ledgers, user profiles, and certificates in AWS S3 (or seamlessly falls back to local storage when deployed without AWS credentials).
- **TraceX Command Center Dashboard & Chrome Extension**
  - Dark cyber-forensic web command center (`/`), analyst login/registration portal (`/login`), live WebSocket progress streaming (`/ws/scans/{task_id}`), and downloadable Chrome Sentinel extension (`/api/extension/download`).

---

## Tech Stack

- **Backend:** Python 3.11, FastAPI, Uvicorn, WebSockets, Pydantic
- **ML & Graph Forensics:** XGBoost, scikit-learn, Pandas, NumPy, NetworkX, python-louvain, Pillow
- **Forensic Evidence & Storage:** ReportLab (Section 65B PDF), SHA-256 Hashing, AWS S3 (`boto3`), Redis, RabbitMQ (`aio-pika`)
- **Frontend & Extension:** HTML5, CSS3, Vanilla JavaScript, Chrome Extension (Manifest V3)
- **Deployment:** Render (`render.yaml`), Docker & Docker Compose

---

## Quick Start (Local Development)

```bash
git clone https://github.com/diptanshu270307-svg/TraceX.git
cd TraceX
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open **http://localhost:8000/** (Dashboard), **http://localhost:8000/login** (Access Portal), or **http://localhost:8000/docs** (Swagger API).

**Demo Analyst Login:** `admin` / `tracex2026!` (or register a new analyst profile directly at `/login`).

---

## One-Click Deploy on Render

This repository includes a production-ready [`render.yaml`](./render.yaml) Blueprint:

1. Open [Render Dashboard](https://dashboard.render.com/) → **New +** → **Blueprint** (or **Web Service**).
2. Connect **`diptanshu270307-svg/TraceX`**.
3. Render automatically configures:
   - **Build Command:** `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command:** `uvicorn gateway.main:app --host 0.0.0.0 --port $PORT`
   - **Health Check:** `/health`
4. *(Optional)* Add `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in Render Environment Variables to enable live AWS S3 persistence (works out of the box with local vault fallback even without AWS keys).
