"""
ml_engine_bridge.py — Translation layer between the ML engine and the graph module.

The ML engine (ml_engine/pipeline.py) produces a result dict shaped like:
    {
      "scan_id":           str,
      "sha256_hash":       str,
      "s3_uri":            str,
      "fraud_score":       int 0-100,
      "risk_level":        "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "classification":    "LEGITIMATE" | "PHISHING" | ...,
      "confidence":        float 0-1,
      "evidence_id":       str,
      "cryptographic_seal": str,
      "forensic_breakdown": {
        "spf": "PASS" | "FAIL",
        "dkim": "PASS" | "FAIL",
        "dmarc": "PASS" | "FAIL",
        "domain_levenshtein": float,
        "domain_entropy": float,
        "relay_hops": int,
        "visual_phish_prob": float 0-1,
      },
      "timestamp": str (ISO),
    }

The graph module (networkx_module/models.py ScanResult) expects:
    {
      scan_id, sender, recipients[], subject, originating_ip, urls[],
      threat_score 0-100, verdict, spf_pass bool, dkim_pass bool,
      dmarc_pass bool, ml_features dict, timestamp ISO,
    }

This file is the glue. It does **not** import the ML engine, so the
graph module stays runnable in environments where torch/transformers/
boto3/redis aren't installed (your tests, the demo, FastAPI workers
that only serve the graph view, etc.).

How to use:
    # Option 1 — you already have a result dict
    from networkx_module import process_scans
    from networkx_module.ml_engine_bridge import ml_result_to_scan_result

    scan = ml_result_to_scan_result(pipeline.predict(...))
    result = process_scans([scan])

    # Option 2 — batch
    from networkx_module.ml_engine_bridge import ml_results_to_scan_results
    scans = ml_results_to_scan_results([result_a, result_b, result_c])
    result = process_scans(scans)

    # Option 3 — when you also have the original raw email metadata
    from networkx_module.ml_engine_bridge import (
        enrich_ml_result_with_raw_metadata,
    )
    enriched = enrich_ml_result_with_raw_metadata(
        ml_result, raw_meta_from_header_extractor,
    )
    scan = ml_result_to_scan_result(enriched)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterable, Optional

# Make this module loadable both as part of the package and as a
# top-level module (the same pattern the rest of the package uses).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from models import ScanResult
else:
    from .models import ScanResult


# ─────────────────────────────────────────────────────────────
# Risk-level mapping
# ─────────────────────────────────────────────────────────────
#
# The ML engine uses uppercase labels (CRITICAL / HIGH / MEDIUM / LOW).
# The graph module's `verdict` field uses lowercase categories
# (clean / suspicious / phishing / malware / bec). Map the former
# to the latter for graph analytics.

_RISK_TO_VERDICT = {
    "CRITICAL": "phishing",
    "HIGH": "phishing",
    "MEDIUM": "suspicious",
    "LOW": "clean",
}

# Classification labels the ML engine may emit → graph module verdict.
# Falls back to risk-level mapping if classification is unrecognized.
_CLASSIFICATION_TO_VERDICT = {
    "PHISHING": "phishing",
    "LEGITIMATE": "clean",
    "SUSPICIOUS": "suspicious",
    "MALWARE": "malware",
    "BEC": "bec",
    "SPAM": "suspicious",
}


def _pass(v: Any) -> Optional[bool]:
    """Normalize PASS/FAIL/bool/None to Optional[bool]."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).strip().upper()
    if s in ("PASS", "TRUE", "1", "YES"):
        return True
    if s in ("FAIL", "FALSE", "0", "NO", "SOFTFAIL"):
        return False
    return None  # NEUTRAL / UNKNOWN / temperror / etc.


def _strip_address(s: str) -> Optional[str]:
    """Extract a bare email address from 'Name <addr@x>' or plain."""
    if not s:
        return None
    if "<" in s and ">" in s:
        inside = s.split("<", 1)[1].split(">", 1)[0].strip()
        if inside:
            return inside.lower()
    s = str(s).strip()
    if "@" in s:
        return s.lower()
    return s.lower() or None


def _urls_from_raw(raw_meta: dict) -> list[str]:
    """Best-effort URL extraction from raw metadata dicts.

    URLs are normalized (strip trailing punctuation, lowercase scheme/host)
    before de-dup so 'https://X.com/a' and 'https://x.com/a.' don't
    both end up in the graph.
    """
    def _normalize(u: str) -> str:
        u = u.rstrip(".,;:!?)")
        # Lowercase scheme + host
        if "://" in u:
            scheme, rest = u.split("://", 1)
            if "/" in rest:
                host, path = rest.split("/", 1)
                return f"{scheme.lower()}://{host.lower()}/{path}"
            return f"{scheme.lower()}://{rest.lower()}"
        return u

    seen: set[str] = set()
    out: list[str] = []
    for key in ("urls", "extracted_urls", "links"):
        v = raw_meta.get(key)
        if isinstance(v, list):
            for u in v:
                if not u:
                    continue
                n = _normalize(str(u))
                if n not in seen:
                    seen.add(n)
                    out.append(n)
        elif isinstance(v, str) and v.strip():
            for p in v.split(","):
                p = p.strip()
                if not p:
                    continue
                n = _normalize(p)
                if n not in seen:
                    seen.add(n)
                    out.append(n)
    # Body fallback: scrape http(s) URLs from the body string
    body = raw_meta.get("body") or raw_meta.get("body_text") or ""
    if isinstance(body, str) and body:
        import re
        for u in re.findall(r"https?://[^\s<>\"')]+", body):
            n = _normalize(u)
            if n not in seen:
                seen.add(n)
                out.append(n)
    return out


def _ips_from_raw(raw_meta: dict) -> list[str]:
    """Extract IP addresses from raw metadata if present."""
    ips: list[str] = []
    for key in ("ips", "extracted_ips", "originating_ips"):
        v = raw_meta.get(key)
        if isinstance(v, list):
            ips.extend(str(i) for i in v if i)
    received = raw_meta.get("received_hops") or raw_meta.get("received")
    if isinstance(received, list):
        import re
        for hop in received:
            if isinstance(hop, str):
                found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hop)
                ips.extend(found)
    # De-dup while preserving order
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


# ─────────────────────────────────────────────────────────────
# Conversion functions
# ─────────────────────────────────────────────────────────────

def enrich_ml_result_with_raw_metadata(
    ml_result: dict,
    raw_meta: Optional[dict] = None,
) -> dict:
    """Optionally combine an ML engine result with raw email metadata.

    The ML engine result already contains everything the graph module
    needs (sender, subject, auth flags, score, classification).
    But URLs and originating IPs are NOT in the ML result — they
    live in the raw metadata the ML engine parsed from the .eml.
    If you have that, pass it here; otherwise the graph node will
    just lack URL/IP attachments.
    """
    if not raw_meta:
        return ml_result
    out = dict(ml_result)
    out.setdefault("_raw_meta", {})
    out["_raw_meta"].update(raw_meta)
    return out


def ml_result_to_scan_result(ml_result: dict) -> ScanResult:
    """Convert a single ML engine result dict to a graph ScanResult.

    Required keys: scan_id, sender (in the raw meta or top-level),
    recipients (in the raw meta or top-level), subject.
    """
    if not isinstance(ml_result, dict):
        raise TypeError(
            f"ml_result must be a dict, got {type(ml_result).__name__}"
        )

    # The ML engine accepts sender as a kwarg and merges it INTO
    # metadata_or_headers, so the canonical place is the input meta.
    # But pipeline.predict ALSO stores some fields on the top-level
    # result. We check both.
    raw = ml_result.get("_raw_meta") or {}
    # The pipeline's `record_scan` only stores sender/recipient/subject
    # + fraud_score/risk_level/classification in DynamoDB. Everything
    # else (urls, ips, body) only lives in the input metadata.
    # So we rely primarily on `_raw_meta` for graph-relevant data.

    # Sender — accept from result, raw, or fallback
    sender = (
        ml_result.get("sender")
        or raw.get("sender")
        or ""
    )
    sender = _strip_address(sender)
    if not sender:
        raise ValueError(
            "ml_result has no usable sender "
            "(looked at result.sender and _raw_meta.sender)"
        )

    # Recipients
    recipients_field = ml_result.get("recipient") or raw.get("recipient") or ""
    if isinstance(recipients_field, list):
        recipients = [
            a for a in (_strip_address(r) for r in recipients_field) if a
        ]
    else:
        recipients = [
            a for a in (
                _strip_address(p)
                for p in str(recipients_field).replace(";", ",").split(",")
            ) if a
        ]
    if not recipients:
        # Graph still works with an empty recipient list, but warn.
        recipients = []

    # Subject
    subject = ml_result.get("subject") or raw.get("subject") or ""

    # Threat score & verdict
    threat_score = ml_result.get("fraud_score")
    if threat_score is not None:
        try:
            threat_score = int(threat_score)
        except (TypeError, ValueError):
            threat_score = None

    classification = str(ml_result.get("classification") or "").upper()
    risk_level = str(ml_result.get("risk_level") or "").upper()
    verdict = (
        _CLASSIFICATION_TO_VERDICT.get(classification)
        or _RISK_TO_VERDICT.get(risk_level)
    )

    # Auth flags — prefer the structured forensic_breakdown if present
    fb = ml_result.get("forensic_breakdown") or {}
    spf_pass = _pass(fb.get("spf") or raw.get("spf"))
    dkim_pass = _pass(fb.get("dkim") or raw.get("dkim"))
    dmarc_pass = _pass(fb.get("dmarc") or raw.get("dmarc"))

    # URLs and IPs come from the raw metadata, not the ML result
    urls = _urls_from_raw(raw)
    ips = _ips_from_raw(raw)
    originating_ip = ips[0] if ips else None

    # ML features — everything forensic/heuristic that doesn't map
    # cleanly to a ScanResult field. Useful for the DB metadata JSONB
    # column and the API's `ml_features` payload.
    ml_features: dict[str, Any] = {}
    if fb:
        for k, v in fb.items():
            ml_features[f"forensic_{k}"] = v
    for k in ("confidence", "classification", "risk_level",
              "evidence_id", "cryptographic_seal", "s3_uri",
              "sha256_hash", "visual_phish_prob"):
        if k in ml_result and ml_result[k] is not None:
            ml_features[k] = ml_result[k]
    if raw:
        for k in ("reply_to", "hops", "relay_hops", "domain_levenshtein",
                  "domain_entropy", "has_punycode", "display_name_spoof",
                  "subject_urgency", "reply_to_mismatch", "suspicious_tld",
                  "subdomain_depth"):
            if k in raw and raw[k] is not None:
                ml_features[k] = raw[k]

    # Timestamp — prefer ML result, fall back to now
    ts = ml_result.get("timestamp")
    if not ts:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()

    return ScanResult(
        scan_id=str(ml_result.get("scan_id") or ""),
        sender=sender,
        recipients=recipients,
        subject=str(subject),
        originating_ip=originating_ip,
        urls=urls,
        threat_score=threat_score,
        verdict=verdict,
        spf_pass=spf_pass,
        dkim_pass=dkim_pass,
        dmarc_pass=dmarc_pass,
        ml_features=ml_features,
        timestamp=str(ts),
    )


def ml_results_to_scan_results(
    ml_results: Iterable[dict],
) -> list[ScanResult]:
    """Convert a batch of ML engine results to ScanResult objects.

    Bad inputs are skipped (a warning is printed to stderr) so a
    single malformed record doesn't break the whole batch.
    """
    out: list[ScanResult] = []
    for r in ml_results:
        try:
            out.append(ml_result_to_scan_result(r))
        except (ValueError, TypeError) as e:
            import sys
            print(
                f"[ml_engine_bridge] skipped scan "
                f"{r.get('scan_id') if isinstance(r, dict) else '?'}: {e}",
                file=sys.stderr,
            )
    return out


def ml_results_dicts(
    ml_results: Iterable[dict],
) -> list[dict]:
    """Like ml_results_to_scan_results but returns plain dicts.

    Useful when you want to feed the result straight into
    process_scans(ml_results_dicts(...)) without first wrapping
    in ScanResult objects.
    """
    return [sr.to_dict() for sr in ml_results_to_scan_results(ml_results)]
