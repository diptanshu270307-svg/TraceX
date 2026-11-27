"""
models.py — Shared data contracts for cross-module integration.

This file defines the exact shapes of data that flow between:
  - ML Pipeline  →  NetworkX module  (ScanResult)
  - NetworkX     →  PostgreSQL       (GraphNode, GraphEdge, CommunityRecord)
  - NetworkX     →  FastAPI/Frontend (GraphExport)

Your ML friend's pipeline should output a ScanResult dict.
PostgreSQL tables are created from the schemas defined here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Optional

import networkx as nx


# ─────────────────────────────────────────────────────────────
# 1. INPUT CONTRACT — What ML pipeline sends to NetworkX
# ─────────────────────────────────────────────────────────────

class ThreatVerdict(str, Enum):
    """ML verdict categories."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALWARE = "malware"
    BEC = "bec"  # Business Email Compromise


@dataclass
class ScanResult:
    """What the ML pipeline produces per email scan.

    This is the INPUT contract — your ML friend should produce dicts
    matching this shape. The NetworkX module consumes these.

    Example dict from ML pipeline:
        {
            "scan_id": "scan-001",
            "sender": "phisher@evil.com",
            "recipients": ["victim@company.com"],
            "subject": "Urgent: Reset Password",
            "originating_ip": "185.220.101.42",
            "urls": ["https://evil.com/phish"],
            "threat_score": 92.5,
            "verdict": "phishing",
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "ml_features": {
                "levenshtein_score": 0.85,
                "entropy": 4.2,
                "url_count": 2
            },
            "timestamp": "2026-09-07T21:00:00Z"
        }
    """

    scan_id: str
    sender: str
    recipients: list[str]
    subject: str = ""
    originating_ip: Optional[str] = None
    urls: list[str] = field(default_factory=list)
    threat_score: Optional[float] = None
    verdict: Optional[str] = None  # ThreatVerdict value
    spf_pass: Optional[bool] = None
    dkim_pass: Optional[bool] = None
    dmarc_pass: Optional[bool] = None
    ml_features: dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Create ScanResult from a dict (e.g., from ML pipeline JSON output).

        Tolerant of extra keys — ignores fields not in the dataclass.
        """
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def to_dict(self) -> dict:
        """Convert to a plain dict for JSON serialization."""
        return asdict(self)


# ─────────────────────────────────────────────────────────────
# 2. OUTPUT CONTRACTS — What NetworkX sends to PostgreSQL / API
# ─────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    """A node record to be stored in PostgreSQL.

    Maps to the `graph_nodes` table.
    """

    node_id: str           # Primary key (e.g., "attacker@evil.com", "domain:evil.com")
    node_type: str         # "email_address", "domain", "ip", "url"
    label: str             # Human-readable label
    community_id: Optional[int] = None
    centrality: float = 0.0
    threat_score: Optional[float] = None
    scan_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_db_row(self) -> tuple:
        """Convert to a tuple for PostgreSQL INSERT."""
        return (
            self.node_id,
            self.node_type,
            self.label,
            self.community_id,
            self.centrality,
            self.threat_score,
            json.dumps(self.scan_ids),
            json.dumps(self.metadata),
            self.created_at,
        )


@dataclass
class GraphEdge:
    """An edge record to be stored in PostgreSQL.

    Maps to the `graph_edges` table.
    """

    source_id: str
    target_id: str
    edge_type: str          # "sent", "belongs_to", "originated_from", etc.
    scan_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_db_row(self) -> tuple:
        """Convert to a tuple for PostgreSQL INSERT."""
        return (
            self.source_id,
            self.target_id,
            self.edge_type,
            self.scan_id,
            json.dumps(self.metadata),
            self.created_at,
        )


@dataclass
class CommunityRecord:
    """A community/cluster record for PostgreSQL.

    Maps to the `graph_communities` table.
    """

    community_id: int
    size: int
    avg_threat_score: Optional[float] = None
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    top_broker_id: Optional[str] = None
    top_broker_centrality: float = 0.0
    risk_level: str = "low"  # "low", "medium", "high", "critical"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GraphExport:
    """Complete graph export for the frontend API response.

    This is what FastAPI returns to the React frontend for visualization.
    """

    nodes: list[dict]
    edges: list[dict]
    communities: list[dict]
    top_brokers: list[dict]
    stats: dict
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────
# 3. CONVERTERS — graph + analysis → DB rows / API payloads
# ─────────────────────────────────────────────────────────────

# Auth-related node attributes that should land in the metadata JSONB column
_AUTH_KEYS = ("spf_pass", "dkim_pass", "dmarc_pass", "verdict", "ml_features")


def graph_to_db_nodes(graph: nx.MultiDiGraph) -> list[GraphNode]:
    """Convert every node in the graph into a GraphNode row.

    Pulls in centrality, community_id, threat_score, scan_ids, and
    authentication metadata already attached to the node.
    """
    nodes: list[GraphNode] = []
    for node_id, data in graph.nodes(data=True):
        metadata: dict[str, Any] = {}
        for key in _AUTH_KEYS:
            if key in data and data[key] is not None:
                metadata[key] = data[key]
        # Any non-standard key goes into metadata too
        for key, value in data.items():
            if key in (
                "node_id", "node_type", "label", "community", "community_id",
                "centrality", "threat_score", "scan_ids",
            ) or key in _AUTH_KEYS:
                continue
            metadata[key] = value

        nodes.append(GraphNode(
            node_id=node_id,
            node_type=data.get("node_type", "unknown"),
            label=data.get("label", node_id),
            community_id=data.get("community") or data.get("community_id"),
            centrality=float(data.get("centrality", 0.0) or 0.0),
            threat_score=data.get("threat_score"),
            scan_ids=list(data.get("scan_ids", []) or []),
            metadata=metadata,
        ))
    return nodes


def graph_to_db_edges(graph: nx.MultiDiGraph) -> list[GraphEdge]:
    """Convert every edge in the graph into a GraphEdge row.

    MultiDiGraph parallel edges each become their own row (with a unique
    scan_id when one is available).
    """
    edges: list[GraphEdge] = []
    for source, target, key, data in graph.edges(keys=True, data=True):
        # Pull everything except the well-known columns into metadata
        metadata: dict[str, Any] = {}
        for k, v in data.items():
            if k in ("edge_type", "scan_id"):
                continue
            metadata[k] = v

        edges.append(GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=data.get("edge_type", "unknown"),
            scan_id=data.get("scan_id"),
            metadata=metadata,
        ))
    return edges


def community_summaries_to_db_records(
    community_summaries: Iterable[dict[str, Any]],
) -> list[CommunityRecord]:
    """Convert analyzer community summaries into CommunityRecord rows."""
    records: list[CommunityRecord] = []
    for summary in community_summaries:
        top_broker = (summary.get("top_brokers") or [{}])[0]
        records.append(CommunityRecord(
            community_id=int(summary["community_id"]),
            size=int(summary["size"]),
            avg_threat_score=summary.get("avg_threat_score"),
            domains=list(summary.get("domains", [])),
            ips=list(summary.get("ips", [])),
            top_broker_id=top_broker.get("id"),
            top_broker_centrality=float(top_broker.get("centrality", 0.0) or 0.0),
            risk_level=summary.get("risk_level", "low"),
        ))
    return records


def build_persistence_payload(
    graph: nx.MultiDiGraph,
    analysis_results: dict[str, Any],
) -> tuple[list[GraphNode], list[GraphEdge], list[CommunityRecord]]:
    """One-shot conversion: graph + analysis → DB-ready rows.

    Returns:
        (nodes, edges, communities) — pass these straight to
        GraphDB.save_nodes / save_edges / save_communities.
    """
    nodes = graph_to_db_nodes(graph)
    edges = graph_to_db_edges(graph)
    communities = community_summaries_to_db_records(
        analysis_results.get("communities", [])
    )
    return nodes, edges, communities
