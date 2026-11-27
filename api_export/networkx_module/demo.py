"""
demo.py — End-to-end demo of the NetworkX graph intelligence module.

Shows the complete pipeline:
  ML scan results (dicts)  →  graph  →  analysis  →  DB rows  →  API export
                                                                →  HTML viz

This is the working reference for:
  - Your ML friend (see how their dicts are consumed)
  - The PostgreSQL/backend integration (see how rows are produced)
  - The FastAPI/React frontend (see the API export shape)

Usage:
    cd networkx_module
    pip install -r requirements.txt
    python demo.py
    → Opens threat_graph.html in your browser
"""

import json
import sys
import webbrowser
from pathlib import Path

# Allow this file to run either as `python demo.py` (flat) or
# `python -m networkx_module.demo` (as part of the package).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

if __package__ in (None, ""):
    from ml_bridge import process_scans
    from visualizer import ThreatGraphVisualizer
    from models import build_persistence_payload
    from api_export import build_api_export
else:
    from .ml_bridge import process_scans
    from .visualizer import ThreatGraphVisualizer
    from .models import build_persistence_payload
    from .api_export import build_api_export


def create_sample_scans() -> list[dict]:
    """Sample ML-pipeline output.

    Each dict matches the ScanResult contract in models.py — this is
    exactly the shape your ML friend's pipeline should emit.
    """
    return [
        # ── Campaign A: Fake IT Support (same IP: 185.220.101.42) ──
        {
            "scan_id": "scan-001",
            "sender": "it-support@micros0ft-security.com",
            "recipients": ["hr@targetcorp.com", "finance@targetcorp.com"],
            "subject": "Urgent: Your account will be suspended",
            "originating_ip": "185.220.101.42",
            "urls": [
                "https://micros0ft-security.com/verify-account",
                "https://bit.ly/3xPhish1",
            ],
            "threat_score": 92,
            "verdict": "phishing",
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "ml_features": {"levenshtein_score": 0.91, "url_count": 2},
            "timestamp": "2026-09-07T08:15:00Z",
        },
        {
            "scan_id": "scan-002",
            "sender": "admin@micr0soft-helpdesk.com",
            "recipients": ["ceo@targetcorp.com"],
            "subject": "Password expires in 24 hours",
            "originating_ip": "185.220.101.42",
            "urls": ["https://micr0soft-helpdesk.com/reset-password"],
            "threat_score": 88,
            "verdict": "phishing",
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "ml_features": {"levenshtein_score": 0.88, "url_count": 1},
            "timestamp": "2026-09-07T08:42:00Z",
        },
        {
            "scan_id": "scan-003",
            "sender": "security@m1crosoft-alerts.com",
            "recipients": ["it-admin@targetcorp.com", "cto@targetcorp.com"],
            "subject": "Security Alert: Unusual sign-in activity",
            "originating_ip": "185.220.101.42",
            "urls": [
                "https://m1crosoft-alerts.com/security-check",
                "https://bit.ly/3xPhish1",
            ],
            "threat_score": 95,
            "verdict": "phishing",
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "ml_features": {"levenshtein_score": 0.94, "url_count": 2},
            "timestamp": "2026-09-07T09:10:00Z",
        },
        # ── Campaign B: Fake Bank Alerts (shared phishing domain) ──
        {
            "scan_id": "scan-004",
            "sender": "alerts@secure-bankofamerica.com",
            "recipients": ["finance@targetcorp.com"],
            "subject": "Suspicious transaction detected on your account",
            "originating_ip": "91.215.85.7",
            "urls": [
                "https://secure-bankofamerica.com/verify-transaction",
                "https://evil-redirect.xyz/bank",
            ],
            "threat_score": 85,
            "verdict": "phishing",
            "spf_pass": False,
            "dkim_pass": True,
            "dmarc_pass": False,
            "ml_features": {"levenshtein_score": 0.82, "url_count": 2},
            "timestamp": "2026-09-07T10:01:00Z",
        },
        {
            "scan_id": "scan-005",
            "sender": "noreply@chase-secure-login.com",
            "recipients": ["cfo@targetcorp.com", "finance@targetcorp.com"],
            "subject": "Your account has been temporarily locked",
            "originating_ip": "91.215.85.12",
            "urls": [
                "https://chase-secure-login.com/unlock",
                "https://evil-redirect.xyz/chase",
            ],
            "threat_score": 82,
            "verdict": "phishing",
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "ml_features": {"levenshtein_score": 0.79, "url_count": 2},
            "timestamp": "2026-09-07T10:23:00Z",
        },
        # ── Legitimate emails (for contrast) ──
        {
            "scan_id": "scan-006",
            "sender": "newsletter@github.com",
            "recipients": ["dev@targetcorp.com"],
            "subject": "GitHub Universe 2026 — Early bird registration",
            "originating_ip": "140.82.112.1",
            "urls": ["https://github.com/universe"],
            "threat_score": 5,
            "verdict": "clean",
            "spf_pass": True,
            "dkim_pass": True,
            "dmarc_pass": True,
            "ml_features": {"levenshtein_score": 0.02, "url_count": 1},
            "timestamp": "2026-09-07T11:00:00Z",
        },
        {
            "scan_id": "scan-007",
            "sender": "billing@aws.amazon.com",
            "recipients": ["it-admin@targetcorp.com"],
            "subject": "Your AWS invoice for August 2026",
            "originating_ip": "54.240.1.1",
            "urls": ["https://console.aws.amazon.com/billing"],
            "threat_score": 3,
            "verdict": "clean",
            "spf_pass": True,
            "dkim_pass": True,
            "dmarc_pass": True,
            "ml_features": {"levenshtein_score": 0.01, "url_count": 1},
            "timestamp": "2026-09-07T11:30:00Z",
        },
    ]


def main():
    print("=" * 60)
    print("  TraceX - NetworkX Graph Intelligence Demo")
    print("=" * 60)

    # ────────────────────────────────────────────────────────────
    # Step 1: ML pipeline output → graph (the bridge)
    # ────────────────────────────────────────────────────────────
    print("\n[1/5] Ingesting 7 ML scan results...")
    scans = create_sample_scans()
    result = process_scans(scans)
    graph = result["graph"]
    analysis = result["analysis"]

    if result["errors"]:
        print(f"   [!] Rejected {len(result['errors'])} malformed scan(s):")
        for raw, err in result["errors"]:
            print(f"      - {err}")

    stats = result["graph_stats"]
    print(f"\n   Graph Stats:")
    print(f"   Nodes: {stats['total_nodes']}")
    print(f"   Edges: {stats['total_edges']}")
    print(f"   Node types: {stats['node_types']}")
    print(f"   Edge types: {stats['edge_types']}")

    # ────────────────────────────────────────────────────────────
    # Step 2: Analysis results
    # ────────────────────────────────────────────────────────────
    print(f"\n[2/5] Threat analysis — {analysis['num_communities']} communities detected")
    for comm in analysis["communities"]:
        print(f"\n   Community {comm['community_id']}  "
              f"[{comm['risk_level'].upper()}]  "
              f"size={comm['size']}")
        if comm["avg_threat_score"] is not None:
            print(f"     Avg Threat Score: {comm['avg_threat_score']}/100")
        if comm["domains"]:
            print(f"     Domains: {', '.join(comm['domains'][:5])}")
        if comm["top_brokers"]:
            top = comm["top_brokers"][0]
            print(f"     Top Broker: {top['label']} (centrality: {top['centrality']:.4f})")

    print(f"\n   Top Broker Nodes (global):")
    for broker in analysis["top_brokers"][:5]:
        print(f"   {broker['label']} ({broker['type']}) — "
              f"centrality: {broker['centrality']:.4f}")

    # ────────────────────────────────────────────────────────────
    # Step 3: PostgreSQL rows (what db.py.save_analysis will write)
    # ────────────────────────────────────────────────────────────
    nodes, edges, communities = build_persistence_payload(graph, analysis)
    print(f"\n[3/5] PostgreSQL payload prepared:")
    print(f"   graph_nodes:       {len(nodes)} rows")
    print(f"   graph_edges:       {len(edges)} rows")
    print(f"   graph_communities: {len(communities)} rows")

    # ────────────────────────────────────────────────────────────
    # Step 4: API export (what FastAPI returns to the React frontend)
    # ────────────────────────────────────────────────────────────
    api_payload = build_api_export(graph, analysis)
    print(f"\n[4/5] API export: {len(api_payload['nodes'])} nodes, "
          f"{len(api_payload['edges'])} edges, "
          f"{api_payload['stats']['high_risk_communities']} high-risk communities")

    # ────────────────────────────────────────────────────────────
    # Step 5: Write outputs to disk
    # ────────────────────────────────────────────────────────────
    # Always write next to this script so the demo works regardless
    # of the directory it was invoked from.
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(exist_ok=True)

    with open(output_dir / "analysis_results.json", "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, default=str)

    with open(output_dir / "api_export.json", "w", encoding="utf-8") as f:
        json.dump(api_payload, f, indent=2, default=str)

    print(f"\n[5/5] Generating interactive graph visualization...")
    viz = ThreatGraphVisualizer(graph)
    html_path = viz.render(
        output_path=str(output_dir / "threat_graph.html"),
        title="TraceX — Email Threat Intelligence Graph",
        color_by="community",
    )

    # ────────────────────────────────────────────────────────────
    # Step 6: Done — open in browser
    # ────────────────────────────────────────────────────────────
    print(f"\n   Output files in: {output_dir.resolve()}")
    print(f"   - analysis_results.json   (full analysis)")
    print(f"   - api_export.json         (FastAPI response shape)")
    print(f"   - threat_graph.html       (interactive viz)")

    print(f"\n   Opening in browser...")
    webbrowser.open(f"file:///{html_path}")

    print(f"\nDone! Hover nodes for threat details.")
    print(f"   Senders sharing an IP (orange edges) are likely the same actor.")
    print(f"   Community color = Louvain cluster; risk_level shows the danger.")


if __name__ == "__main__":
    main()
