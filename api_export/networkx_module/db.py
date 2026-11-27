"""
db.py — PostgreSQL integration layer for the graph module.

Handles:
  - Table creation (graph_nodes, graph_edges, graph_communities)
  - Bulk insert of graph data after analysis (atomic or per-table)
  - Query methods for the FastAPI backend to read graph data

Uses psycopg2 for PostgreSQL. Connection config comes from environment
variables or is passed directly.

Environment variables:
  TRACEX_DB_HOST     (default: localhost)
  TRACEX_DB_PORT     (default: 5432)
  TRACEX_DB_NAME     (default: tracex)
  TRACEX_DB_USER     (default: tracex)
  TRACEX_DB_PASSWORD (required in production)
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from typing import Any, Generator, Optional

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from .models import GraphNode, GraphEdge, CommunityRecord


# ─────────────────────────────────────────────────────────────
# SQL Schema
# ─────────────────────────────────────────────────────────────

SCHEMA_SQL = """
-- Graph nodes: every entity in the threat graph
CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id         TEXT PRIMARY KEY,
    node_type       TEXT NOT NULL,           -- 'email_address', 'domain', 'ip', 'url'
    label           TEXT NOT NULL,
    community_id    INTEGER,
    centrality      REAL DEFAULT 0.0,
    threat_score    REAL,
    scan_ids        JSONB DEFAULT '[]',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_community ON graph_nodes(community_id);
CREATE INDEX IF NOT EXISTS idx_nodes_centrality ON graph_nodes(centrality DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_threat ON graph_nodes(threat_score DESC);

-- Graph edges: relationships between entities
CREATE TABLE IF NOT EXISTS graph_edges (
    id              SERIAL PRIMARY KEY,
    source_id       TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    target_id       TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    edge_type       TEXT NOT NULL,           -- 'sent', 'belongs_to', 'originated_from', etc.
    scan_id         TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(edge_type);
CREATE INDEX IF NOT EXISTS idx_edges_scan ON graph_edges(scan_id);

-- Detected communities / threat clusters
CREATE TABLE IF NOT EXISTS graph_communities (
    community_id        INTEGER PRIMARY KEY,
    size                INTEGER NOT NULL,
    avg_threat_score    REAL,
    domains             JSONB DEFAULT '[]',
    ips                 JSONB DEFAULT '[]',
    top_broker_id       TEXT,
    top_broker_centrality REAL DEFAULT 0.0,
    risk_level          TEXT DEFAULT 'low',   -- 'low', 'medium', 'high', 'critical'
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);
"""


class GraphDB:
    """PostgreSQL persistence layer for the threat graph.

    Usage:
        db = GraphDB()                              # Uses env vars
        db = GraphDB(host="localhost", dbname="tracex", user="tracex", password="secret")
        db.create_tables()
        db.save_analysis(graph, analysis_results)   # atomic all-in-one

        # Or step by step:
        db.save_nodes(nodes)
        db.save_edges(edges)
        db.save_communities(communities)

        # Query (for FastAPI)
        nodes = db.get_nodes_by_community(community_id=3)
        brokers = db.get_top_brokers(limit=10)
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        dbname: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        if not HAS_PSYCOPG2:
            raise ImportError(
                "psycopg2 is required for PostgreSQL integration. "
                "Install it with: pip install psycopg2-binary"
            )

        self.conn_params = {
            "host": host or os.environ.get("TRACEX_DB_HOST", "localhost"),
            "port": port or int(os.environ.get("TRACEX_DB_PORT", "5432")),
            "dbname": dbname or os.environ.get("TRACEX_DB_NAME", "tracex"),
            "user": user or os.environ.get("TRACEX_DB_USER", "tracex"),
            "password": password or os.environ.get("TRACEX_DB_PASSWORD", ""),
        }

    @contextmanager
    def _get_conn(self) -> Generator:
        """Context manager for database connections."""
        conn = psycopg2.connect(**self.conn_params)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_tables(self) -> None:
        """Create all graph tables if they don't exist."""
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    # ── WRITE operations ──

    def save_nodes(self, nodes: list[GraphNode]) -> int:
        """Upsert graph nodes into PostgreSQL.

        Uses ON CONFLICT to update existing nodes (e.g., when
        re-analyzing with new scan data).

        Returns:
            Number of nodes upserted.
        """
        if not nodes:
            return 0

        sql = """
            INSERT INTO graph_nodes
                (node_id, node_type, label, community_id, centrality,
                 threat_score, scan_ids, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (node_id) DO UPDATE SET
                community_id = EXCLUDED.community_id,
                centrality = EXCLUDED.centrality,
                threat_score = COALESCE(EXCLUDED.threat_score, graph_nodes.threat_score),
                scan_ids = EXCLUDED.scan_ids,
                metadata = graph_nodes.metadata || EXCLUDED.metadata,
                updated_at = NOW()
        """

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                rows = [n.to_db_row() for n in nodes]
                psycopg2.extras.execute_batch(cur, sql, rows, page_size=100)
                return len(rows)

    def save_edges(self, edges: list[GraphEdge]) -> int:
        """Insert graph edges into PostgreSQL.

        Returns:
            Number of edges inserted.
        """
        if not edges:
            return 0

        sql = """
            INSERT INTO graph_edges
                (source_id, target_id, edge_type, scan_id, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                rows = [e.to_db_row() for e in edges]
                psycopg2.extras.execute_batch(cur, sql, rows, page_size=100)
                return len(rows)

    def save_communities(self, communities: list[CommunityRecord]) -> int:
        """Upsert community records.

        Returns:
            Number of communities upserted.
        """
        if not communities:
            return 0

        sql = """
            INSERT INTO graph_communities
                (community_id, size, avg_threat_score, domains, ips,
                 top_broker_id, top_broker_centrality, risk_level, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (community_id) DO UPDATE SET
                size = EXCLUDED.size,
                avg_threat_score = EXCLUDED.avg_threat_score,
                domains = EXCLUDED.domains,
                ips = EXCLUDED.ips,
                top_broker_id = EXCLUDED.top_broker_id,
                top_broker_centrality = EXCLUDED.top_broker_centrality,
                risk_level = EXCLUDED.risk_level,
                updated_at = NOW()
        """

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                rows = []
                for c in communities:
                    rows.append((
                        c.community_id,
                        c.size,
                        c.avg_threat_score,
                        json.dumps(c.domains),
                        json.dumps(c.ips),
                        c.top_broker_id,
                        c.top_broker_centrality,
                        c.risk_level,
                        c.created_at,
                    ))
                psycopg2.extras.execute_batch(cur, sql, rows, page_size=100)
                return len(rows)

    def save_analysis(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
        communities: list[CommunityRecord],
    ) -> dict[str, int]:
        """Persist an entire analysis result atomically.

        All three tables are written in a single transaction — either
        everything lands or nothing does. Use this for production
        ingestion to avoid partial state.
        """
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                if nodes:
                    sql_nodes = """
                        INSERT INTO graph_nodes
                            (node_id, node_type, label, community_id, centrality,
                             threat_score, scan_ids, metadata, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (node_id) DO UPDATE SET
                            community_id = EXCLUDED.community_id,
                            centrality = EXCLUDED.centrality,
                            threat_score = COALESCE(EXCLUDED.threat_score, graph_nodes.threat_score),
                            scan_ids = EXCLUDED.scan_ids,
                            metadata = graph_nodes.metadata || EXCLUDED.metadata,
                            updated_at = NOW()
                    """
                    psycopg2.extras.execute_batch(
                        cur, sql_nodes, [n.to_db_row() for n in nodes], page_size=100
                    )

                if edges:
                    sql_edges = """
                        INSERT INTO graph_edges
                            (source_id, target_id, edge_type, scan_id, metadata, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    psycopg2.extras.execute_batch(
                        cur, sql_edges, [e.to_db_row() for e in edges], page_size=100
                    )

                if communities:
                    sql_communities = """
                        INSERT INTO graph_communities
                            (community_id, size, avg_threat_score, domains, ips,
                             top_broker_id, top_broker_centrality, risk_level, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (community_id) DO UPDATE SET
                            size = EXCLUDED.size,
                            avg_threat_score = EXCLUDED.avg_threat_score,
                            domains = EXCLUDED.domains,
                            ips = EXCLUDED.ips,
                            top_broker_id = EXCLUDED.top_broker_id,
                            top_broker_centrality = EXCLUDED.top_broker_centrality,
                            risk_level = EXCLUDED.risk_level,
                            updated_at = NOW()
                    """
                    rows = [
                        (
                            c.community_id, c.size, c.avg_threat_score,
                            json.dumps(c.domains), json.dumps(c.ips),
                            c.top_broker_id, c.top_broker_centrality,
                            c.risk_level, c.created_at,
                        )
                        for c in communities
                    ]
                    psycopg2.extras.execute_batch(
                        cur, sql_communities, rows, page_size=100
                    )

        return {
            "nodes": len(nodes),
            "edges": len(edges),
            "communities": len(communities),
        }

    # ── READ operations (for FastAPI backend) ──

    def get_all_nodes(self) -> list[dict]:
        """Get all graph nodes."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM graph_nodes ORDER BY centrality DESC")
                return [dict(row) for row in cur.fetchall()]

    def get_all_edges(self) -> list[dict]:
        """Get all graph edges."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM graph_edges ORDER BY created_at DESC")
                return [dict(row) for row in cur.fetchall()]

    def get_nodes_by_community(self, community_id: int) -> list[dict]:
        """Get all nodes belonging to a specific community."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM graph_nodes WHERE community_id = %s ORDER BY centrality DESC",
                    (community_id,),
                )
                return [dict(row) for row in cur.fetchall()]

    def get_nodes_by_type(self, node_type: str) -> list[dict]:
        """Get all nodes of a specific type (email_address, domain, ip, url)."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM graph_nodes WHERE node_type = %s ORDER BY centrality DESC",
                    (node_type,),
                )
                return [dict(row) for row in cur.fetchall()]

    def get_top_brokers(self, limit: int = 10) -> list[dict]:
        """Get the top broker nodes by centrality."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM graph_nodes WHERE centrality > 0 ORDER BY centrality DESC LIMIT %s",
                    (limit,),
                )
                return [dict(row) for row in cur.fetchall()]

    def get_communities(self) -> list[dict]:
        """Get all detected communities."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM graph_communities ORDER BY avg_threat_score DESC NULLS LAST"
                )
                return [dict(row) for row in cur.fetchall()]

    def get_high_risk_communities(self, min_threat: float = 50.0) -> list[dict]:
        """Get communities with avg threat score above threshold."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM graph_communities WHERE avg_threat_score >= %s ORDER BY avg_threat_score DESC",
                    (min_threat,),
                )
                return [dict(row) for row in cur.fetchall()]

    def get_edges_for_node(self, node_id: str) -> list[dict]:
        """Get all edges connected to a specific node."""
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM graph_edges WHERE source_id = %s OR target_id = %s",
                    (node_id, node_id),
                )
                return [dict(row) for row in cur.fetchall()]

    def get_graph_for_scan(self, scan_id: str) -> dict:
        """Get all nodes and edges related to a specific scan.

        Useful for showing the graph of a single email analysis.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Get edges for this scan
                cur.execute(
                    "SELECT * FROM graph_edges WHERE scan_id = %s",
                    (scan_id,),
                )
                edges = [dict(row) for row in cur.fetchall()]

                # Get all node IDs referenced by these edges
                node_ids = set()
                for e in edges:
                    node_ids.add(e["source_id"])
                    node_ids.add(e["target_id"])

                # Get node details
                nodes = []
                if node_ids:
                    cur.execute(
                        "SELECT * FROM graph_nodes WHERE node_id = ANY(%s)",
                        (list(node_ids),),
                    )
                    nodes = [dict(row) for row in cur.fetchall()]

                return {"nodes": nodes, "edges": edges}

    def clear_graph(self) -> None:
        """Delete all graph data. Use carefully!"""
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE graph_edges, graph_nodes, graph_communities CASCADE")

    def get_schema_sql(self) -> str:
        """Return the SQL schema string (for manual table creation)."""
        return SCHEMA_SQL
