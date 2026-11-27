"""
ml_engine_bridge_example.py — Reference for the ML team.

Shows how to wire ml_engine.pipeline.predict() output into the
NetworkX graph module, end-to-end. Drop this file into your
notebook / pipeline driver and call `run()`.

Run from the project root:
    python -m networkx_module.ml_engine_bridge_example
or from inside the networkx_module directory:
    python ml_engine_bridge_example.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the package importable when this file is run as a flat script
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from networkx_module.ml_engine_bridge import (
    enrich_ml_result_with_raw_metadata,
    ml_results_to_scan_results,
    ml_results_dicts,
)
from networkx_module import (
    process_scans,
    build_persistence_payload,
    build_api_export,
    GraphDB,  # lazy-imported; requires psycopg2
)


def run():
    """1. Get ML engine results
       2. Convert them to ScanResults
       3. Build the graph + run analysis
       4. Hand the rows to PostgreSQL
       5. Hand the JSON to the FastAPI/React frontend
    """
    # ── 1. ML engine inference ─────────────────────────────────
    # Option A — call the real pipeline (requires torch, transformers,
    # boto3, redis, AWS creds, etc.)
    #
    #     from ml_engine.pipeline import TraceXMLPipeline
    #     from ml_engine.features.header_extractor import HeaderForensicExtractor
    #     extractor = HeaderForensicExtractor()
    #     parsed = extractor.extract_from_eml_file("incoming.eml")
    #     pipeline = TraceXMLPipeline()
    #     ml_result = pipeline.predict(
    #         image_path_or_obj="rendered.png",
    #         metadata_or_headers=parsed["meta"],
    #     )
    #     # The header extractor returned `meta` (sender, subject, ...,
    #     # body, urls, ips) but the pipeline result doesn't carry those
    #     # forward. We attach them via enrich_ml_result_with_raw_metadata
    #     # so the graph gets URL + IP attachments.
    #     ml_result = enrich_ml_result_with_raw_metadata(ml_result, parsed["meta"])

    # Option B — already have a list of result dicts (e.g. from DynamoDB)
    ml_results = _example_ml_results()

    # ── 2. Convert to ScanResult ──────────────────────────────
    scans = ml_results_dicts(ml_results)
    # OR:  scans = [sr.to_dict() for sr in ml_results_to_scan_results(ml_results)]

    # ── 3. Build the graph + run analysis ─────────────────────
    result = process_scans(scans)
    graph = result["graph"]
    analysis = result["analysis"]

    print(f"Graph: {graph.number_of_nodes()} nodes, "
          f"{graph.number_of_edges()} edges")
    print(f"Communities: {analysis['num_communities']}")
    for c in analysis["communities"]:
        print(f"  C{c['community_id']} [{c['risk_level'].upper()}] "
              f"size={c['size']} avg_score={c['avg_threat_score']}")

    # ── 4. Persist to PostgreSQL ───────────────────────────────
    nodes, edges, communities = build_persistence_payload(graph, analysis)
    try:
        db = GraphDB()  # uses TRACEX_DB_* env vars
        db.create_tables()
        counts = db.save_analysis(nodes, edges, communities)
        print(f"Saved to PostgreSQL: {counts}")
    except ImportError:
        print("(psycopg2 not installed — skipping DB write)")
    except Exception as e:
        print(f"(PostgreSQL unavailable: {e})")

    # ── 5. JSON for the React frontend ────────────────────────
    api_payload = build_api_export(graph, analysis)
    Path("api_export.json").write_text(
        json.dumps(api_payload, indent=2, default=str), encoding="utf-8"
    )
    print(f"API export written: api_export.json "
          f"({len(api_payload['nodes'])} nodes, "
          f"{len(api_payload['edges'])} edges, "
          f"{api_payload['stats']['high_risk_communities']} "
          f"high-risk communities)")


def _example_ml_results():
    """Synthetic ML engine results — replace with real pipeline.predict() output."""
    return [
        {
            "scan_id": "ml-demo-001",
            "sha256_hash": "9f4d7e2b" + "0" * 56,
            "fraud_score": 94,
            "risk_level": "CRITICAL",
            "classification": "PHISHING",
            "confidence": 0.96,
            "forensic_breakdown": {
                "spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL",
                "domain_levenshtein": 0.92, "domain_entropy": 4.5,
                "relay_hops": 4, "visual_phish_prob": 0.95,
            },
            "timestamp": "2026-09-07T20:42:18Z",
            "_raw_meta": {
                "sender": "State Bank Alerts <alerts@sbi-corp-demo.test>",
                "recipient": "finance@corp.internal",
                "subject": "Urgent Corporate Invoice Verification Required",
                "urls": ["https://sbi-corp-demo.test/verify"],
                "ips": ["203.0.113.42"],
                "body": "Verify: https://sbi-corp-demo.test/verify",
            },
        },
        {
            "scan_id": "ml-demo-002",
            "sha256_score": 6,
            "fraud_score": 6,
            "risk_level": "LOW",
            "classification": "LEGITIMATE",
            "confidence": 0.98,
            "forensic_breakdown": {
                "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
                "domain_levenshtein": 0.0, "domain_entropy": 2.4,
                "relay_hops": 2, "visual_phish_prob": 0.02,
            },
            "timestamp": "2026-09-07T11:30:00Z",
            "_raw_meta": {
                "sender": "Amazon Web Services <no-reply-aws@amazon.com>",
                "recipient": "devops@corp.internal",
                "subject": "AWS Billing Notification: August Statement Available",
                "urls": ["https://console.aws.amazon.com/billing"],
                "ips": ["54.240.1.1"],
            },
        },
    ]


if __name__ == "__main__":
    run()
