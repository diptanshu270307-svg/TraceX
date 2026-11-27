"""
api_export.py — Convert internal graph + analysis state into the JSON
shape that FastAPI returns to the React frontend.

Keeps the wire format decoupled from the internal MultiDiGraph so the
frontend team has a stable contract even if we refactor internals later.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx

# Make module loadable both as part of the package and as a flat module
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))


def _serialize_node(node_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Flatten a single graph node into a JSON-safe dict."""
    return {
        "id": node_id,
        "type": data.get("node_type", "unknown"),
        "label": data.get("label", node_id),
        "community": data.get("community") or data.get("community_id"),
        "centrality": float(data.get("centrality", 0.0) or 0.0),
        "threat_score": data.get("threat_score"),
        "scan_ids": list(data.get("scan_ids", []) or []),
        "auth": {
            k: data[k]
            for k in ("spf_pass", "dkim_pass", "dmarc_pass")
            if k in data and data[k] is not None
        },
        "verdict": data.get("verdict"),
    }


def _serialize_edge(source: str, target: str, data: dict[str, Any]) -> dict[str, Any]:
    """Flatten a single graph edge into a JSON-safe dict."""
    return {
        "source": source,
        "target": target,
        "type": data.get("edge_type", "unknown"),
        "scan_id": data.get("scan_id"),
        "subject": data.get("subject"),
        "threat_score": data.get("threat_score"),
    }


def build_api_export(
    graph: nx.MultiDiGraph,
    analysis: dict[str, Any] | None = None,
    *,
    include_all_nodes: bool = True,
) -> dict[str, Any]:
    """Produce the JSON payload the FastAPI endpoint will return.

    Args:
        graph: The analyzed MultiDiGraph (must have community + centrality
               on nodes if analysis has been run).
        analysis: Output of ThreatGraphAnalyzer.run_full_analysis().
                  If None, only the graph_stats and nodes/edges are filled.
        include_all_nodes: If False, omit nodes with centrality == 0
                           (useful for trimming huge graphs for the UI).

    Returns:
        A GraphExport-shaped dict, JSON-serializable.
    """
    analysis = analysis or {}
    communities = analysis.get("communities", []) or []
    top_brokers = analysis.get("top_brokers", []) or []

    # ── Nodes ──
    nodes: list[dict[str, Any]] = []
    for node_id, data in graph.nodes(data=True):
        centrality = float(data.get("centrality", 0.0) or 0.0)
        if not include_all_nodes and centrality == 0:
            continue
        nodes.append(_serialize_node(node_id, data))

    # ── Edges ──
    edges: list[dict[str, Any]] = []
    for source, target, data in graph.edges(data=True):
        edges.append(_serialize_edge(source, target, data))

    # ── Stats ──
    node_type_counts: dict[str, int] = {}
    for _, data in graph.nodes(data=True):
        t = data.get("node_type", "unknown")
        node_type_counts[t] = node_type_counts.get(t, 0) + 1

    edge_type_counts: dict[str, int] = {}
    for _, _, data in graph.edges(data=True):
        t = data.get("edge_type", "unknown")
        edge_type_counts[t] = edge_type_counts.get(t, 0) + 1

    stats = {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "node_types": node_type_counts,
        "edge_types": edge_type_counts,
        "num_communities": len(communities),
        "high_risk_communities": sum(
            1 for c in communities if c.get("risk_level") in ("high", "critical")
        ),
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "communities": communities,
        "top_brokers": top_brokers,
        "stats": stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def filter_export_for_community(
    export: dict[str, Any],
    community_id: int,
) -> dict[str, Any]:
    """Return a copy of `export` containing only nodes/edges of one community.

    Useful for the "drill into a cluster" UI flow.
    """
    member_ids = {
        m["id"]
        for c in export.get("communities", [])
        if c.get("community_id") == community_id
        for m in c.get("members", [])
    }

    nodes = [n for n in export.get("nodes", []) if n["id"] in member_ids]
    edges = [
        e for e in export.get("edges", [])
        if e["source"] in member_ids and e["target"] in member_ids
    ]
    communities = [
        c for c in export.get("communities", [])
        if c.get("community_id") == community_id
    ]

    return {
        **export,
        "nodes": nodes,
        "edges": edges,
        "communities": communities,
        "stats": {
            **export.get("stats", {}),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "num_communities": len(communities),
            "filtered_to_community": community_id,
        },
    }
