"""
NetworkX Graph Intelligence Module for Email Threat Detection (SIH 2026)

This module is the central integration point for the threat-graph side of
TraceX. It owns:
  - Building a MultiDiGraph of emails, senders, recipients, IPs, URLs, domains
  - Detecting threat-actor communities (Louvain) and broker nodes (betweenness)
  - Persisting the graph to PostgreSQL
  - Producing the JSON shape consumed by the FastAPI/React frontend
  - Rendering an interactive pyvis HTML visualization

The single-call entry point is `ml_bridge.process_scans`, which accepts
the scan dicts your ML pipeline emits and runs the whole pipeline.

Module map:
  graph_builder.py   — nx.MultiDiGraph construction
  analysis.py        — Louvain + betweenness centrality + risk classification
  visualizer.py      — pyvis HTML rendering
  models.py          — shared data contracts (ScanResult, GraphNode, GraphEdge,
                       CommunityRecord, GraphExport) + DB-row converters
  db.py              — PostgreSQL persistence layer (psycopg2)
  ml_bridge.py       — ML pipeline → graph → analysis (one-shot pipeline)
  api_export.py      — graph + analysis → JSON for the FastAPI backend
"""

from .graph_builder import ThreatGraphBuilder, EmailRecord
from .analysis import ThreatGraphAnalyzer, classify_risk
from .visualizer import ThreatGraphVisualizer
from .models import (
    ScanResult,
    ThreatVerdict,
    GraphNode,
    GraphEdge,
    CommunityRecord,
    GraphExport,
    graph_to_db_nodes,
    graph_to_db_edges,
    community_summaries_to_db_records,
    build_persistence_payload,
)
from .ml_bridge import (
    process_scans,
    process_scans_from_jsonl,
    process_scans_from_json,
)
from .ml_engine_bridge import (
    ml_result_to_scan_result,
    ml_results_to_scan_results,
    ml_results_dicts,
    enrich_ml_result_with_raw_metadata,
)
from .api_export import build_api_export, filter_export_for_community

# db.GraphDB is imported lazily — it requires psycopg2 at import time
__all__ = [
    # Graph construction
    "ThreatGraphBuilder",
    "EmailRecord",
    # Analysis
    "ThreatGraphAnalyzer",
    "classify_risk",
    # Visualization
    "ThreatGraphVisualizer",
    # Data contracts
    "ScanResult",
    "ThreatVerdict",
    "GraphNode",
    "GraphEdge",
    "CommunityRecord",
    "GraphExport",
    # Converters
    "graph_to_db_nodes",
    "graph_to_db_edges",
    "community_summaries_to_db_records",
    "build_persistence_payload",
    # ML bridge
    "process_scans",
    "process_scans_from_jsonl",
    "process_scans_from_json",
    # ML engine bridge (ML pipeline result → ScanResult)
    "ml_result_to_scan_result",
    "ml_results_to_scan_results",
    "ml_results_dicts",
    "enrich_ml_result_with_raw_metadata",
    # API export
    "build_api_export",
    "filter_export_for_community",
]


def __getattr__(name: str):
    """Lazy import for db.GraphDB so the module loads without psycopg2."""
    if name == "GraphDB":
        from .db import GraphDB
        return GraphDB
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
