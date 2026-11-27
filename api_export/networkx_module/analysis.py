"""
analysis.py — Graph-based threat intelligence analysis.

Provides:
  1. Louvain community detection — groups nodes into threat actor clusters
  2. Betweenness centrality — identifies broker/hub nodes
  3. Risk classification — labels each community as low/medium/high/critical
  4. Threat summary — per-community aggregation (members, brokers, scores)

All analysis is run on an undirected simple projection of the original
MultiDiGraph because python-louvain and betweenness_centrality expect
undirected, non-multigraph input. Results are written back onto the
original directed graph so callers can access them via node attributes.
"""

from __future__ import annotations

from typing import Any

try:
    import community as community_louvain  # python-louvain
except ImportError:
    community_louvain = None
import networkx as nx


# Risk thresholds (avg_threat_score 0-100 → risk level)
RISK_THRESHOLDS = [
    (0.0, "low"),
    (30.0, "medium"),
    (60.0, "high"),
    (80.0, "critical"),
]


def classify_risk(avg_threat_score: float | None, size: int) -> str:
    """Classify a community's risk from its avg threat score and size.

    A small cluster with high scores is still concerning, so we boost the
    level for tiny but dangerous clusters (size <= 3 with score >= 70).
    """
    if avg_threat_score is None:
        # No email nodes scored — base it purely on size
        if size <= 2:
            return "low"
        if size <= 5:
            return "low"
        return "medium"

    level = "low"
    for threshold, name in RISK_THRESHOLDS:
        if avg_threat_score >= threshold:
            level = name

    # Small, very hot clusters are almost always malicious infrastructure
    if size <= 3 and avg_threat_score >= 70 and level != "critical":
        level = "critical"

    return level


class ThreatGraphAnalyzer:
    """Runs graph analytics on a ThreatGraphBuilder's MultiDiGraph.

    Usage:
        analyzer = ThreatGraphAnalyzer(builder.get_graph())
        results = analyzer.run_full_analysis()
    """

    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph
        # Convert to undirected simple graph for community detection
        # (Louvain requires undirected, non-multi graph)
        self._undirected: nx.Graph = nx.Graph(graph)
        self._communities: dict[str, int] = {}
        self._centrality: dict[str, float] = {}

    # ── Detection ──

    def detect_communities(self, resolution: float = 1.0) -> dict[str, int]:
        """Run Louvain community detection.

        Args:
            resolution: Higher values produce more, smaller communities.
                        1.0 is the default. Use >1 to split large clusters,
                        <1 to merge.

        Returns:
            Dict mapping node_id → community_id (int).
            Nodes in the same community are likely part of the same
            threat campaign or actor group.
        """
        if self._undirected.number_of_nodes() == 0:
            self._communities = {}
            return self._communities

        if community_louvain is not None:
            self._communities = community_louvain.best_partition(
                self._undirected,
                resolution=resolution,
                random_state=42,
            )
        else:
            try:
                from networkx.algorithms.community import louvain_communities
                comm_sets = louvain_communities(self._undirected, seed=42, resolution=resolution)
                self._communities = {}
                for comm_id, node_set in enumerate(comm_sets):
                    for node in node_set:
                        self._communities[node] = comm_id
            except Exception:
                self._communities = {}
                for comm_id, comp in enumerate(nx.connected_components(self._undirected)):
                    for node in comp:
                        self._communities[node] = comm_id

        # Store community IDs on the original directed graph nodes
        for node_id, comm_id in self._communities.items():
            if self.graph.has_node(node_id):
                self.graph.nodes[node_id]["community"] = comm_id

        return self._communities

    def compute_centrality(self) -> dict[str, float]:
        """Compute betweenness centrality on the undirected projection.

        Returns:
            Dict mapping node_id → centrality score (0.0 to 1.0).
            High-centrality nodes are brokers connecting different parts
            of the threat network — key targets for investigation.
        """
        if self._undirected.number_of_nodes() == 0:
            self._centrality = {}
            return self._centrality

        self._centrality = nx.betweenness_centrality(
            self._undirected,
            normalized=True,
        )

        # Store centrality on the original directed graph nodes
        for node_id, score in self._centrality.items():
            if self.graph.has_node(node_id):
                self.graph.nodes[node_id]["centrality"] = round(score, 6)

        return self._centrality

    # ── Summaries ──

    def get_community_summary(self) -> list[dict[str, Any]]:
        """Generate a summary for each detected community.

        Returns a list of dicts, one per community, containing:
          - community_id
          - size (number of nodes)
          - members (list of node IDs and their types)
          - top_brokers (highest centrality nodes in this community)
          - avg_threat_score (average threat score of email_address nodes)
          - domains (unique domains in this community)
          - ips (unique IPs in this community)
          - risk_level (low / medium / high / critical)
        """
        if not self._communities:
            self.detect_communities()
        if not self._centrality:
            self.compute_centrality()

        # Group nodes by community
        comm_groups: dict[int, list[str]] = {}
        for node_id, comm_id in self._communities.items():
            comm_groups.setdefault(comm_id, []).append(node_id)

        summaries = []
        for comm_id in sorted(comm_groups.keys()):
            members = comm_groups[comm_id]
            member_details = []
            threat_scores = []
            domains: set[str] = set()
            ips: set[str] = set()

            for node_id in members:
                node_data = self.graph.nodes.get(node_id, {})
                node_type = node_data.get("node_type", "unknown")
                member_details.append({
                    "id": node_id,
                    "type": node_type,
                    "label": node_data.get("label", node_id),
                    "centrality": self._centrality.get(node_id, 0.0),
                })

                # Collect threat scores from email_address nodes only
                if node_type == "email_address" and node_data.get("threat_score") is not None:
                    threat_scores.append(node_data["threat_score"])

                # Collect domains and IPs by node type
                if node_type == "domain":
                    domains.add(node_data.get("label", node_id))
                elif node_type == "ip":
                    ips.add(node_data.get("label", node_id))

            # Sort members by centrality to find top brokers
            member_details.sort(key=lambda x: x["centrality"], reverse=True)
            top_brokers = [m for m in member_details[:3] if m["centrality"] > 0]

            avg_threat = (
                round(sum(threat_scores) / len(threat_scores), 1)
                if threat_scores
                else None
            )

            risk_level = classify_risk(avg_threat, len(members))

            summaries.append({
                "community_id": comm_id,
                "size": len(members),
                "members": member_details,
                "top_brokers": top_brokers,
                "avg_threat_score": avg_threat,
                "domains": sorted(domains),
                "ips": sorted(ips),
                "risk_level": risk_level,
            })

        # Sort communities by risk priority (critical first, then size)
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        summaries.sort(
            key=lambda x: (risk_order.get(x["risk_level"], 4), -x["size"])
        )
        return summaries

    def get_top_brokers(self, n: int = 10) -> list[dict[str, Any]]:
        """Return the top N nodes by betweenness centrality.

        These are the most important "broker" nodes — they connect
        different parts of the threat network.
        """
        if not self._centrality:
            self.compute_centrality()

        sorted_nodes = sorted(
            self._centrality.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        brokers = []
        for node_id, score in sorted_nodes[:n]:
            if score == 0:
                break
            node_data = self.graph.nodes.get(node_id, {})
            brokers.append({
                "id": node_id,
                "type": node_data.get("node_type", "unknown"),
                "label": node_data.get("label", node_id),
                "centrality": round(score, 6),
                "community": node_data.get("community"),
                "threat_score": node_data.get("threat_score"),
            })

        return brokers

    def run_full_analysis(self, resolution: float = 1.0) -> dict[str, Any]:
        """Run all analyses and return a complete results dict.

        This is the main entry point — call this and you get everything
        needed for the API response, the HTML viz, and the PostgreSQL
        persistence layer in one go.
        """
        self.detect_communities(resolution=resolution)
        self.compute_centrality()
        communities = self.get_community_summary()
        top_brokers = self.get_top_brokers(n=10)

        return {
            "graph_stats": {
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
            },
            "num_communities": len(set(self._communities.values())) if self._communities else 0,
            "communities": communities,
            "top_brokers": top_brokers,
        }
