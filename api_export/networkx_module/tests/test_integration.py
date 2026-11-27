"""
tests/test_integration.py — End-to-end contract test.

Pins the cross-module data contract so the ML pipeline team, the
PostgreSQL backend, and the FastAPI/React frontend can evolve
independently without breaking each other.

Run with either:
    cd networkx_module
    python -m unittest tests.test_integration
or
    python -m unittest discover -s networkx_module/tests -t networkx_module
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running as `python -m unittest tests.test_integration` from
# the networkx_module directory (without a parent __init__.py).
_THIS_DIR = Path(__file__).resolve().parent
_MODULE_DIR = _THIS_DIR.parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))
# Also enable `from networkx_module import …` style
_PARENT = _MODULE_DIR.parent
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))

if __package__ in (None, "", "tests"):
    from ml_bridge import (
        process_scans,
        process_scans_from_jsonl,
        process_scans_from_json,
    )
    from ml_engine_bridge import (
        ml_result_to_scan_result,
        ml_results_to_scan_results,
        ml_results_dicts,
        enrich_ml_result_with_raw_metadata,
    )
    from analysis import classify_risk
    from models import (
        ScanResult,
        GraphNode,
        GraphEdge,
        CommunityRecord,
        build_persistence_payload,
        graph_to_db_nodes,
        graph_to_db_edges,
    )
    from api_export import build_api_export, filter_export_for_community
    from visualizer import ThreatGraphVisualizer
else:
    from ..ml_bridge import (
        process_scans,
        process_scans_from_jsonl,
        process_scans_from_json,
    )
    from ..ml_engine_bridge import (
        ml_result_to_scan_result,
        ml_results_to_scan_results,
        ml_results_dicts,
        enrich_ml_result_with_raw_metadata,
    )
    from ..analysis import classify_risk
    from ..models import (
        ScanResult,
        GraphNode,
        GraphEdge,
        CommunityRecord,
        build_persistence_payload,
        graph_to_db_nodes,
        graph_to_db_edges,
    )
    from ..api_export import build_api_export, filter_export_for_community
    from ..visualizer import ThreatGraphVisualizer


SAMPLE_SCANS = [
    {
        "scan_id": "t-001",
        "sender": "attacker@evil.com",
        "recipients": ["victim@corp.com"],
        "subject": "Urgent",
        "originating_ip": "1.2.3.4",
        "urls": ["https://evil.com/x"],
        "threat_score": 90,
        "verdict": "phishing",
        "spf_pass": False,
        "dkim_pass": False,
        "dmarc_pass": False,
    },
    {
        "scan_id": "t-002",
        "sender": "attacker2@evil.com",
        "recipients": ["victim2@corp.com"],
        "subject": "Reset",
        "originating_ip": "1.2.3.4",  # same IP — must link
        "urls": ["https://evil.com/y"],
        "threat_score": 88,
        "verdict": "phishing",
    },
    {
        "scan_id": "t-003",
        "sender": "legit@github.com",
        "recipients": ["dev@corp.com"],
        "subject": "Newsletter",
        "originating_ip": "140.82.112.1",
        "urls": ["https://github.com/blog"],
        "threat_score": 2,
        "verdict": "clean",
    },
]


class TestMLBridge(unittest.TestCase):
    """The ML pipeline contract."""

    def test_process_scans_returns_full_bundle(self):
        result = process_scans(SAMPLE_SCANS)

        self.assertIn("graph", result)
        self.assertIn("analysis", result)
        self.assertIn("graph_stats", result)
        self.assertIn("scan_results", result)
        self.assertIn("errors", result)

        self.assertEqual(result["graph_stats"]["total_nodes"], 14)  # exact
        self.assertEqual(len(result["errors"]), 0)
        self.assertEqual(len(result["scan_results"]), 3)

    def test_rejects_malformed_input(self):
        result = process_scans([
            {"scan_id": "ok-1", "sender": "a@b.com", "recipients": []},
            "not-json",
            {"sender": "missing-scan-id"},
        ])

        self.assertEqual(len(result["scan_results"]), 1)
        self.assertEqual(len(result["errors"]), 2)

    def test_jsonl_round_trip(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            for scan in SAMPLE_SCANS:
                f.write(json.dumps(scan) + "\n")
            path = f.name

        try:
            result = process_scans_from_jsonl(path)
            self.assertEqual(len(result["scan_results"]), 3)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_json_round_trip(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(SAMPLE_SCANS, f)
            path = f.name

        try:
            result = process_scans_from_json(path)
            self.assertEqual(len(result["scan_results"]), 3)
        finally:
            Path(path).unlink(missing_ok=True)


class TestAnalysis(unittest.TestCase):
    """Risk classification & community detection."""

    def test_risk_levels(self):
        self.assertEqual(classify_risk(None, 1), "low")
        self.assertEqual(classify_risk(50, 10), "medium")
        self.assertEqual(classify_risk(65, 10), "high")
        self.assertEqual(classify_risk(85, 10), "critical")
        # small + dangerous → critical
        self.assertEqual(classify_risk(75, 2), "critical")
        self.assertEqual(classify_risk(10, 10), "low")

    def test_communities_have_risk_level(self):
        result = process_scans(SAMPLE_SCANS)
        for c in result["analysis"]["communities"]:
            self.assertIn("risk_level", c)
            self.assertIn(c["risk_level"], {"low", "medium", "high", "critical"})

    def test_ips_are_separated_from_domains(self):
        """Regression test for the old typo: IPs were added to the domains set."""
        result = process_scans(SAMPLE_SCANS)
        all_ips: set[str] = set()
        all_domains: set[str] = set()
        for c in result["analysis"]["communities"]:
            for ip in c.get("ips", []):
                all_ips.add(ip)
            for d in c.get("domains", []):
                all_domains.add(d)

        # Domains must NOT contain IP strings
        self.assertEqual(all_ips & all_domains, set())


class TestPersistencePayload(unittest.TestCase):
    """PostgreSQL row converters."""

    def test_nodes_have_all_required_columns(self):
        result = process_scans(SAMPLE_SCANS)
        nodes, edges, communities = build_persistence_payload(
            result["graph"], result["analysis"]
        )

        for n in nodes:
            self.assertIsInstance(n, GraphNode)
            self.assertIsInstance(n.to_db_row(), tuple)
            self.assertEqual(len(n.to_db_row()), 9)
        for e in edges:
            self.assertIsInstance(e, GraphEdge)
            self.assertIsInstance(e.to_db_row(), tuple)
            self.assertEqual(len(e.to_db_row()), 6)
        for c in communities:
            self.assertIsInstance(c, CommunityRecord)
            self.assertIn(c.risk_level, {"low", "medium", "high", "critical"})

    def test_community_id_and_centrality_on_nodes(self):
        result = process_scans(SAMPLE_SCANS)
        nodes = graph_to_db_nodes(result["graph"])

        # At least one node must have community_id and centrality > 0
        communities_present = [n for n in nodes if n.community_id is not None]
        high_centrality = [n for n in nodes if n.centrality > 0]
        self.assertGreater(len(communities_present), 0)
        self.assertGreater(len(high_centrality), 0)


class TestAPIExport(unittest.TestCase):
    """FastAPI/React wire format."""

    def test_export_shape(self):
        result = process_scans(SAMPLE_SCANS)
        export = build_api_export(result["graph"], result["analysis"])

        for key in ("nodes", "edges", "communities", "top_brokers", "stats", "generated_at"):
            self.assertIn(key, export)

        # Stats must be a JSON-serializable dict
        json.dumps(export["stats"])

        # All node entries must have the keys the React UI expects
        for n in export["nodes"]:
            self.assertIn("id", n)
            self.assertIn("type", n)
            self.assertIn("community", n)
            self.assertIn("centrality", n)

    def test_filter_to_community(self):
        result = process_scans(SAMPLE_SCANS)
        export = build_api_export(result["graph"], result["analysis"])

        # Pick any community with members
        target = next(
            (c for c in export["communities"] if c.get("members")), None
        )
        if target is None:
            self.skipTest("no community with members in sample data")

        filtered = filter_export_for_community(export, target["community_id"])
        self.assertEqual(len(filtered["communities"]), 1)
        # All remaining nodes must be members of the target community
        member_ids = {m["id"] for m in target["members"]}
        for n in filtered["nodes"]:
            self.assertIn(n["id"], member_ids)


class TestMLEngineBridge(unittest.TestCase):
    """Pin the contract between ml_engine.pipeline.predict() and graph ScanResult."""

    ML_RESULT_PHISH = {
        "scan_id": "ml-001",
        "sha256_hash": "9f4d7e2b" + "a" * 56,
        "s3_uri": "s3://tracex-forensic-vault/raw-emails/ml-001.eml",
        "fraud_score": 92,
        "risk_level": "CRITICAL",
        "classification": "PHISHING",
        "confidence": 0.96,
        "evidence_id": "EV-ML-001",
        "cryptographic_seal": "0x" + "a" * 64,
        "forensic_breakdown": {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "domain_levenshtein": 0.91,
            "domain_entropy": 4.2,
            "relay_hops": 4,
            "visual_phish_prob": 0.94,
        },
        "timestamp": "2026-09-07T20:42:18Z",
        # The ML pipeline accepts sender/recipient/subject as top-level
        # kwargs in addition to the input metadata dict. Both shapes
        # should be accepted by the bridge.
        "sender": "alerts@sbi-corp-demo.test",
        "recipient": "finance@company-demo.test, cfo@company-demo.test",
        "subject": "Urgent Corporate Invoice Verification Required",
    }

    ML_RESULT_LEGIT = {
        "scan_id": "ml-002",
        "fraud_score": 8,
        "risk_level": "LOW",
        "classification": "LEGITIMATE",
        "confidence": 0.98,
        "forensic_breakdown": {
            "spf": "PASS", "dkim": "PASS", "dmarc": "PASS",
            "domain_levenshtein": 0.0, "domain_entropy": 2.4,
            "relay_hops": 2, "visual_phish_prob": 0.02,
        },
        "timestamp": "2026-09-07T11:30:00Z",
        # NOTE: no top-level sender here — the bridge should still find
        # it via `_raw_meta`.
        "_raw_meta": {
            "sender": "GitHub <noreply@github.com>",
            "recipient": "dev@company-demo.test",
            "subject": "Your weekly digest",
            "body": "Check out https://github.com/blog/this-week",
        },
    }

    def test_critical_phish_becomes_phishing_verdict(self):
        sr = ml_result_to_scan_result(self.ML_RESULT_PHISH)
        self.assertIsInstance(sr, ScanResult)
        self.assertEqual(sr.scan_id, "ml-001")
        self.assertEqual(sr.sender, "alerts@sbi-corp-demo.test")
        self.assertEqual(sr.recipients, [
            "finance@company-demo.test", "cfo@company-demo.test",
        ])
        self.assertEqual(sr.subject, "Urgent Corporate Invoice Verification Required")
        self.assertEqual(sr.threat_score, 92)
        self.assertEqual(sr.verdict, "phishing")
        self.assertEqual(sr.spf_pass, False)
        self.assertEqual(sr.dkim_pass, False)
        self.assertEqual(sr.dmarc_pass, False)
        # ML features should carry the forensic breakdown + metadata
        self.assertEqual(sr.ml_features["forensic_visual_phish_prob"], 0.94)
        self.assertEqual(sr.ml_features["forensic_relay_hops"], 4)
        self.assertEqual(sr.ml_features["classification"], "PHISHING")
        self.assertEqual(sr.ml_features["risk_level"], "CRITICAL")
        # timestamp preserved
        self.assertEqual(sr.timestamp, "2026-09-07T20:42:18Z")

    def test_legit_email_becomes_clean_verdict(self):
        sr = ml_result_to_scan_result(self.ML_RESULT_LEGIT)
        self.assertEqual(sr.verdict, "clean")
        self.assertEqual(sr.threat_score, 8)
        self.assertTrue(sr.spf_pass)
        self.assertTrue(sr.dkim_pass)
        self.assertTrue(sr.dmarc_pass)
        # Sender extracted from "Name <addr>" form
        self.assertEqual(sr.sender, "noreply@github.com")
        # Body URL got scraped into urls[]
        self.assertIn("https://github.com/blog/this-week", sr.urls)

    def test_enrichment_adds_urls_and_ips(self):
        enriched = enrich_ml_result_with_raw_metadata(
            self.ML_RESULT_PHISH,
            {
                "urls": ["https://login.phish.test/a", "https://bit.ly/3xPhish"],
                "ips": ["185.220.101.42", "91.215.85.7"],
                "body": "Click here: https://login.phish.test/a or https://bit.ly/3xPhish",
            },
        )
        sr = ml_result_to_scan_result(enriched)
        self.assertEqual(sr.originating_ip, "185.220.101.42")
        self.assertEqual(sr.urls, [
            "https://login.phish.test/a", "https://bit.ly/3xPhish",
        ])

    def test_batch_skips_bad_inputs(self):
        results = ml_results_to_scan_results([
            self.ML_RESULT_PHISH,
            "not a dict",
            {"scan_id": "no-sender"},  # missing sender
            self.ML_RESULT_LEGIT,
        ])
        self.assertEqual(len(results), 2)
        self.assertEqual([r.scan_id for r in results], ["ml-001", "ml-002"])

    def test_end_to_end_through_graph_pipeline(self):
        """The full pipeline: ML results → bridge → process_scans → graph + analysis."""
        scans_dicts = ml_results_dicts([
            self.ML_RESULT_PHISH, self.ML_RESULT_LEGIT,
        ])
        result = process_scans(scans_dicts)

        # 2 senders + 3 recipients (1 shared) + 3 domains + 1 url = 9
        self.assertEqual(result["graph_stats"]["total_nodes"], 9)
        # sent (3) + belongs_to (5) + contains_url (1) + url_hosted_on (1) = 10
        self.assertEqual(result["graph_stats"]["total_edges"], 10)
        # No errors — both ML results are valid
        self.assertEqual(result["errors"], [])
        # The phish should be in a critical community
        criticals = [
            c for c in result["analysis"]["communities"]
            if c["risk_level"] == "critical"
        ]
        self.assertGreaterEqual(len(criticals), 1)
        # The phish sender + its domain must both appear as graph nodes
        all_nodes = list(result["graph"].nodes)
        self.assertIn("alerts@sbi-corp-demo.test", all_nodes)
        self.assertIn("domain:sbi-corp-demo.test", all_nodes)

    def test_risk_level_fallback_when_classification_unknown(self):
        ml = dict(self.ML_RESULT_PHISH)
        ml["classification"] = "WEIRD_NEW_LABEL"
        sr = ml_result_to_scan_result(ml)
        # CRITICAL risk → phishing verdict (the risk-level fallback)
        self.assertEqual(sr.verdict, "phishing")

    def test_malware_and_bec_classifications(self):
        for cls, expected in [
            ("MALWARE", "malware"),
            ("BEC", "bec"),
            ("SPAM", "suspicious"),
        ]:
            ml = dict(self.ML_RESULT_PHISH)
            ml["classification"] = cls
            sr = ml_result_to_scan_result(ml)
            self.assertEqual(sr.verdict, expected, f"class={cls}")


class TestVisualizer(unittest.TestCase):
    """HTML rendering still works after the threat-color refactor."""

    def test_renders_html(self):
        result = process_scans(SAMPLE_SCANS)
        with tempfile.TemporaryDirectory() as tmp:
            html_path = Path(tmp) / "graph.html"
            viz = ThreatGraphVisualizer(result["graph"])
            out = viz.render(output_path=str(html_path))
            self.assertTrue(Path(out).exists())
            self.assertGreater(Path(out).stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
