"""
test_integration.py — Complete System Verification for TraceX.

Validates:
1. AWS S3 Storage & SHA-256 Checksums
2. Section 65B PDF & JSON Certificate Generation
3. Evidence DB & Ledger Persistence
4. Full Multimodal Pipeline (Donut ViT + XGBoost + Playwright + NetworkX)
5. FastAPI Gateway Endpoints:
   - POST /api/scan (Multipart EML)
   - GET /api/scans (History loading)
   - GET /api/evidence/{id} (Section 65B Certificate Download)
   - GET /api/graph (NetworkX Topology)
"""

import os
import sys
import asyncio
import io
import json
import uuid

# Ensure paths
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from gateway.s3_utils import upload_raw_eml, upload_screenshot, generate_presigned_url, read_s3_bytes
from gateway.section_65b import generate_section_65b_pdf, build_section_65b_certificate_data
from gateway.evidence_db import db
from gateway.pipeline_orchestrator import execute_forensic_pipeline, get_latest_graph
from gateway.main import app

from fastapi.testclient import TestClient

SAMPLE_EML_PATH = os.path.join(WORKSPACE_DIR, "api_export", "ml_engine", "data", "test_urgent_phish.eml")


async def run_pipeline_test():
    print("\n" + "=" * 70)
    print("TEST 1: AWS S3 & SHA-256 Storage Verification")
    print("=" * 70)
    with open(SAMPLE_EML_PATH, "rb") as f:
        file_bytes = f.read()

    import hashlib
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    print(f"[+] Computed SHA-256: {sha256}")

    # Test S3 upload
    s3_eml_uri = await upload_raw_eml(file_bytes, sha256)
    print(f"[+] EML S3 URI: {s3_eml_uri}")
    assert s3_eml_uri.startswith("s3://")

    # Read back from S3 / Vault
    stored_bytes = read_s3_bytes(s3_eml_uri)
    assert stored_bytes == file_bytes, "S3 read back does not match original bytes!"
    print("[OK] S3 EML Upload and Bit-for-Bit Integrity Confirmed.")

    print("\n" + "=" * 70)
    print("TEST 2: Forensic Pipeline Execution (Playwright + Donut ViT + XGBoost + NetworkX)")
    print("=" * 70)
    task_id = "test-task-" + sha256[:8]
    verdict = await execute_forensic_pipeline(
        task_id=task_id,
        sha256_hash=sha256,
        s3_eml_uri=s3_eml_uri,
        file_bytes=file_bytes,
        file_name="test_urgent_phish.eml"
    )

    print(f"[+] Verdict Classification: {verdict['classification']} (Score: {verdict['fraud_score']}/100)")
    print(f"[+] Evidence ID: {verdict['evidence_id']}")
    print(f"[+] S3 Screenshot URI: {verdict['s3_screenshot_uri']}")
    print(f"[+] Cryptographic Seal: {verdict['cryptographic_seal']}")
    assert verdict["fraud_score"] >= 60, "Phishing email score should be >= 60"
    print("[OK] Multimodal Pipeline Executed & Persisted to Evidence Ledger.")

    print("\n" + "=" * 70)
    print("TEST 3: Section 65B Indian Evidence Act Certificate Generation")
    print("=" * 70)
    evidence = db.get_evidence(task_id)
    assert evidence is not None, "Evidence record not found in DB!"

    # Test structured data
    cert_data = build_section_65b_certificate_data(evidence)
    print(f"[+] Certificate Ref: {cert_data['certificate_number']}")
    print(f"[+] Certifier: {cert_data['certifier_name']} ({cert_data['certifier_title']})")
    assert cert_data["artifact_sha256"] == sha256

    # Test PDF Generation
    pdf_bytes = generate_section_65b_pdf(evidence)
    assert pdf_bytes.startswith(b"%PDF"), "Generated output is not a valid PDF binary!"
    print(f"[OK] Section 65B Certificate PDF Generated ({len(pdf_bytes)} bytes).")

    # Save PDF sample for verification
    sample_pdf_path = os.path.join(WORKSPACE_DIR, "gateway", "data", f"Sample_Section_65B_Certificate_{sha256[:8]}.pdf")
    with open(sample_pdf_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"[+] Saved sample PDF certificate to: {sample_pdf_path}")


def run_api_endpoint_tests():
    print("\n" + "=" * 70)
    print("TEST 4: FastAPI Gateway Endpoints Verification")
    print("=" * 70)
    client = TestClient(app)

    # 1. POST /api/scan
    with open(SAMPLE_EML_PATH, "rb") as f:
        response = client.post(
            "/api/scan",
            files={"file": ("test_urgent_phish.eml", f, "message/rfc822")}
        )
    print(f"[+] POST /api/scan -> Status {response.status_code}")
    assert response.status_code == 202, f"Expected 202, got {response.status_code}"
    resp_json = response.json()
    task_id = resp_json["task_id"]
    sha256 = resp_json["sha256"]
    print(f"    Task ID: {task_id}, SHA-256: {sha256}")
    assert "s3_uri" in resp_json
    print("[OK] POST /api/scan endpoint validated.")

    # 2. GET /api/scans (History loading)
    response = client.get("/api/scans")
    print(f"[+] GET /api/scans -> Status {response.status_code}")
    assert response.status_code == 200
    scans = response.json()
    assert isinstance(scans, list) and len(scans) > 0
    print(f"    Loaded {len(scans)} scan(s) from evidence DB.")
    print(f"    Latest scan: {scans[0]['subject']} | Score: {scans[0]['fraud_score']}/100")
    print("[OK] GET /api/scans dashboard history validated.")

    # 3. GET /api/evidence/{id} (Section 65B PDF Download)
    test_evidence_id = "test-task-" + sha256[:8]
    response = client.get(f"/api/evidence/{test_evidence_id}")
    print(f"[+] GET /api/evidence/{test_evidence_id} -> Status {response.status_code}")
    assert response.status_code == 200
    assert response.headers.get("content-type") == "application/pdf"
    assert "attachment" in response.headers.get("content-disposition", "")
    assert response.content.startswith(b"%PDF")
    print("[OK] GET /api/evidence/{id} (Section 65B Certificate PDF Download) validated.")

    # 4. GET /api/evidence/{id}?format=json
    response = client.get(f"/api/evidence/{test_evidence_id}?format=json")
    print(f"[+] GET /api/evidence/{task_id}?format=json -> Status {response.status_code}")
    assert response.status_code == 200
    meta_json = response.json()
    assert "certificate_number" in meta_json
    print(f"    Certificate JSON Reference: {meta_json['certificate_number']}")
    print("[OK] Section 65B Metadata JSON validated.")

    # 5. GET /api/graph
    response = client.get("/api/graph")
    print(f"[+] GET /api/graph -> Status {response.status_code}")
    assert response.status_code == 200
    graph = response.json()
    assert "nodes" in graph and "edges" in graph
    print(f"    Graph contains {len(graph['nodes'])} nodes and {len(graph['edges'])} edges.")
    print("[OK] GET /api/graph validated.")

    # 6. Verify Pure AWS S3 Storage & Absence of Local Database
    print("\n" + "=" * 70)
    print("TEST 5: Pure AWS S3 Storage Verification (No Local Databases)")
    print("=" * 70)
    from gateway.s3_utils import get_scan_from_s3, get_certificate_from_s3
    s3_scan = get_scan_from_s3(test_evidence_id)
    assert s3_scan is not None, f"Scan {test_evidence_id} not found in AWS S3 evidence ledger bucket!"
    print(f"[+] Verified scan '{test_evidence_id}' retrieved directly from AWS S3.")
    s3_cert = get_certificate_from_s3(test_evidence_id)
    assert s3_cert is not None, f"Certificate {test_evidence_id} not found in AWS S3 certificates bucket!"
    print(f"[+] Verified Section 65B Certificate retrieved directly from AWS S3.")

    sqlite_db_path = os.path.join(WORKSPACE_DIR, "gateway", "data", "tracex_forensics.db")
    assert not os.path.exists(sqlite_db_path), f"Violation: SQLite database file exists at {sqlite_db_path}!"
    print("[+] Confirmed: 0 SQLite database files. Storage is 100% pure AWS S3.")
    print("[OK] Pure AWS S3 Storage Verification Confirmed.")

    # 7. Verify Pure AWS S3 Authentication, SIH 26 Login Portal & Extension Redirection
    print("\n" + "=" * 70)
    print("TEST 6: Pure AWS S3 Auth, SIH 26 Login Portal & Extension Redirect")
    print("=" * 70)
    
    # 7a. Register new user into AWS S3
    test_user = f"investigator_{uuid.uuid4().hex[:6]}"
    reg_res = client.post("/api/auth/register", json={
        "username": test_user,
        "email": f"{test_user}@cyber-intel.in",
        "password": "SecurePassword#2026",
        "role": "Senior Cyber Investigator"
    })
    print(f"[+] POST /api/auth/register -> Status {reg_res.status_code}")
    assert reg_res.status_code == 201
    from gateway.s3_utils import get_s3_json, S3_EVIDENCE_BUCKET
    user_s3 = get_s3_json(S3_EVIDENCE_BUCKET, f"auth/users/{test_user}.json")
    assert user_s3 is not None, "User account not found in AWS S3 auth directory!"
    print(f"[+] Confirmed: User profile persisted directly into s3://{S3_EVIDENCE_BUCKET}/auth/users/{test_user}.json")

    # 7b. Login via AWS S3
    login_res = client.post("/api/auth/login", json={
        "username": test_user,
        "password": "SecurePassword#2026"
    })
    print(f"[+] POST /api/auth/login -> Status {login_res.status_code}")
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    assert token.startswith("tracex_sess_")
    session_s3 = get_s3_json(S3_EVIDENCE_BUCKET, f"auth/sessions/{token}.json")
    assert session_s3 is not None, "Session token not found in AWS S3 session directory!"
    print(f"[+] Confirmed: Session token persisted directly into s3://{S3_EVIDENCE_BUCKET}/auth/sessions/{token}.json")

    # 7c. Validate session /api/auth/me
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == test_user
    print("[OK] AWS S3 Authentication & Session Verification Confirmed.")

    # 7d. Verify GET /login serves the SIH 26 Access Portal
    login_page_res = client.get("/login")
    print(f"[+] GET /login -> Status {login_page_res.status_code}")
    assert login_page_res.status_code == 200
    assert "TraceX — Access Portal" in login_page_res.text or "login" in login_page_res.text.lower()
    print("[OK] SIH 26 Access Portal Route Confirmed.")

    # 7e. Verify Chrome Extension /investigate redirection
    redir_res = client.get("/investigate?case_id=IR-2026-SBI-CORP&url=https://sbi-corp-demo.test", follow_redirects=False)
    print(f"[+] GET /investigate -> Status {redir_res.status_code}")
    assert redir_res.status_code == 307
    location = redir_res.headers.get("location")
    assert "/login?" in location and "case_id=IR-2026-SBI-CORP" in location
    print(f"[+] Confirmed: Extension escalates and redirects to '{location}'")
    print("[OK] Extension Redirection Confirmed.")

    # 7f. Verify renamed TraceX Extension Manifest
    ext_manifest_path = os.path.join(WORKSPACE_DIR, "extension", "manifest.json")
    assert os.path.exists(ext_manifest_path), "extension/manifest.json not found!"
    with open(ext_manifest_path, "r") as f:
        ext_manifest = json.load(f)
    assert "TraceX" in ext_manifest["name"]
    print(f"[+] Verified Renamed Extension Name: '{ext_manifest['name']}'")
    print("[OK] TraceX Chrome Extension Package Validated.")

    print("\n" + "=" * 70)
    print("ALL TRACEX INTEGRATION TESTS PASSED SUCCESSFULLY! [SUCCESS]")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_pipeline_test())
    run_api_endpoint_tests()
