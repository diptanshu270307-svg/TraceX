"""
ml_bridge.py — Integration glue between the ML pipeline and the graph module.

The ML pipeline produces ScanResult dicts (see models.ScanResult). This file
provides a single high-level entry point that:

  1. Accepts scan dicts from any source — list, JSON file, JSONL stream,
     or already-parsed ScanResult objects.
  2. Validates them and rejects malformed records with a clear error.
  3. Builds the graph.
  4. Runs analysis.
  5. Returns a complete result bundle ready for PostgreSQL and FastAPI.

The function `process_scans` is the only thing your ML friend needs to
know about. It is safe to call repeatedly as new scans arrive.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, Union

# Allow this module to be imported either as part of the package
# (`from networkx_module.ml_bridge import …`) or as a top-level
# module by test runners that pre-pend the module directory.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from graph_builder import EmailRecord, ThreatGraphBuilder
    from analysis import ThreatGraphAnalyzer
    from models import ScanResult
else:
    from .graph_builder import EmailRecord, ThreatGraphBuilder
    from .analysis import ThreatGraphAnalyzer
    from .models import ScanResult

# A scan can come in as a dict, a ScanResult, or a JSON string
ScanInput = Union[dict, str, ScanResult]


def _coerce(record: ScanInput) -> ScanResult:
    """Coerce any of the supported input shapes into a ScanResult.

    Raises:
        ValueError: if the input cannot be parsed.
    """
    if isinstance(record, ScanResult):
        return record

    if isinstance(record, str):
        try:
            record = json.loads(record)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON for scan record: {e}") from e

    if not isinstance(record, dict):
        raise ValueError(
            f"Scan record must be a dict, JSON string, or ScanResult, "
            f"got {type(record).__name__}"
        )

    if "scan_id" not in record or "sender" not in record:
        raise ValueError(
            f"Scan record missing required field(s) — need 'scan_id' and 'sender', "
            f"got keys: {list(record.keys())}"
        )

    return ScanResult.from_dict(record)


def _scan_result_to_email_record(scan: ScanResult) -> EmailRecord:
    """Translate the ML-facing ScanResult into the graph-builder's EmailRecord.

    Only the fields used for graph construction are forwarded; ml_features
    stays on the ScanResult for downstream consumers (DB metadata, API).
    """
    return EmailRecord(
        scan_id=scan.scan_id,
        sender=scan.sender,
        recipients=list(scan.recipients or []),
        subject=scan.subject or "",
        originating_ip=scan.originating_ip,
        urls=list(scan.urls or []),
        threat_score=scan.threat_score,
        spf_pass=scan.spf_pass,
        dkim_pass=scan.dkim_pass,
        dmarc_pass=scan.dmarc_pass,
    )


def process_scans(
    scans: Iterable[ScanInput],
    *,
    run_analysis: bool = True,
    resolution: float = 1.0,
) -> dict[str, Any]:
    """Take a stream of ML scan results, build the graph, run analysis.

    Args:
        scans: Any iterable of scan records (dicts, JSON strings, or
               ScanResult instances).
        run_analysis: If True (default), run community detection +
                      centrality. If False, only build the graph.
        resolution: Louvain resolution parameter (higher = more, smaller
                    communities).

    Returns:
        A dict with keys:
          - builder      : ThreatGraphBuilder (holds the MultiDiGraph)
          - graph        : nx.MultiDiGraph
          - graph_stats  : node/edge type counts
          - analysis     : full analysis results dict (or None)
          - scan_results : list[ScanResult] that were processed
          - errors       : list of (input, error) tuples for rejected inputs
    """
    builder = ThreatGraphBuilder()
    scan_results: list[ScanResult] = []
    errors: list[tuple[Any, str]] = []

    for raw in scans:
        try:
            scan = _coerce(raw)
        except ValueError as e:
            errors.append((raw, str(e)))
            continue

        scan_results.append(scan)
        builder.add_email(_scan_result_to_email_record(scan))

        # Stash verdict + ml_features on the sender node so they survive
        # into persistence and the API response
        if scan.sender and builder.graph.has_node(scan.sender.lower().strip()):
            sender_node = scan.sender.lower().strip()
            if scan.verdict is not None:
                builder.graph.nodes[sender_node]["verdict"] = scan.verdict
            if scan.ml_features:
                builder.graph.nodes[sender_node]["ml_features"] = dict(scan.ml_features)

    graph = builder.get_graph()
    graph_stats = builder.get_stats()

    analysis: dict[str, Any] | None = None
    if run_analysis and graph.number_of_nodes() > 0:
        analyzer = ThreatGraphAnalyzer(graph)
        analysis = analyzer.run_full_analysis(resolution=resolution)

    return {
        "builder": builder,
        "graph": graph,
        "graph_stats": graph_stats,
        "analysis": analysis,
        "scan_results": scan_results,
        "errors": errors,
    }


def process_scans_from_jsonl(
    path: str | Path,
    *,
    run_analysis: bool = True,
    resolution: float = 1.0,
) -> dict[str, Any]:
    """Convenience: stream a JSONL file of scans.

    Each line of the file is one scan JSON object. Blank lines are
    ignored. The file is read lazily so this works for very large
    inputs.
    """
    def _gen():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield line

    return process_scans(_gen(), run_analysis=run_analysis, resolution=resolution)


def process_scans_from_json(
    path: str | Path,
    *,
    run_analysis: bool = True,
    resolution: float = 1.0,
) -> dict[str, Any]:
    """Convenience: load a JSON file containing a list of scan dicts."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(
            f"Expected a JSON list of scan records, got {type(data).__name__}"
        )
    return process_scans(data, run_analysis=run_analysis, resolution=resolution)
