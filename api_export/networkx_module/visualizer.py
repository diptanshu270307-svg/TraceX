"""
visualizer.py — Interactive HTML graph visualization using pyvis.

Color scheme by node type:
  - email_address  → red/orange (threat actors) or blue (recipients)
  - domain         → purple
  - ip             → yellow
  - url            → cyan/teal

Node size is proportional to betweenness centrality.
Nodes are colored by community when communities are detected.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

try:
    from pyvis.network import Network
except ImportError:
    Network = None

# Make module loadable both as part of the package and as a flat module
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))


# Color palette for communities (up to 12 distinct communities)
COMMUNITY_COLORS = [
    "#e74c3c",  # red
    "#3498db",  # blue
    "#2ecc71",  # green
    "#f39c12",  # orange
    "#9b59b6",  # purple
    "#1abc9c",  # teal
    "#e67e22",  # dark orange
    "#ec407a",  # pink
    "#26c6da",  # cyan
    "#ff7043",  # deep orange
    "#ab47bc",  # deep purple
    "#66bb6a",  # light green
]

# Fallback colors by node type (used when no community is assigned)
NODE_TYPE_COLORS = {
    "email_address": "#e74c3c",
    "domain": "#9b59b6",
    "ip": "#f1c40f",
    "url": "#1abc9c",
}

# Email-address color by threat score (only used when color_by == "threat")
THREAT_COLORS = [
    (0,   "#3498db"),  # blue   — clean
    (30,  "#f1c40f"),  # yellow — suspicious
    (60,  "#e67e22"),  # orange — high
    (80,  "#e74c3c"),  # red    — critical
]

# Shape by node type
NODE_TYPE_SHAPES = {
    "email_address": "dot",
    "domain": "diamond",
    "ip": "triangle",
    "url": "square",
}

EDGE_COLORS = {
    "sent": "#e74c3c",
    "belongs_to": "#95a5a6",
    "originated_from": "#f1c40f",
    "contains_url": "#1abc9c",
    "url_hosted_on": "#9b59b6",
    "same_ip": "#e67e22",
}


class ThreatGraphVisualizer:
    """Generates an interactive HTML visualization of the threat graph.

    Usage:
        viz = ThreatGraphVisualizer(builder.get_graph())
        viz.render("threat_graph.html")
    """

    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph

    def render(
        self,
        output_path: str = "threat_graph.html",
        height: str = "900px",
        width: str = "100%",
        title: str = "TraceX — Email Threat Intelligence Graph",
        color_by: str = "community",
        physics: bool = True,
        notebook: bool = False,
    ) -> str:
        """Render the graph as an interactive HTML file.

        Args:
            output_path: Path to save the HTML file.
            height: Height of the canvas.
            width: Width of the canvas.
            title: Page title.
            color_by: "community" (color by Louvain cluster),
                      "type" (color by node type), or
                      "threat" (email_address nodes colored by threat score).
            physics: Enable physics simulation for layout.
            notebook: Set True if running in Jupyter.

        Returns:
            Absolute path to the generated HTML file.
        """
        if Network is None:
            raise RuntimeError("pyvis is not installed. ThreatGraphVisualizer requires pyvis.")
        net = Network(
            height=height,
            width=width,
            directed=True,
            notebook=notebook,
            bgcolor="#0a0a0a",
            font_color="#ffffff",
            heading=title,
        )

        # Physics configuration for nice layout
        if physics:
            net.force_atlas_2based(
                gravity=-80,
                central_gravity=0.01,
                spring_length=120,
                spring_strength=0.05,
                damping=0.4,
            )
        else:
            net.toggle_physics(False)

        # ── Add nodes ──
        for node_id, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            label = data.get("label", node_id)
            centrality = data.get("centrality", 0.0)
            community_id = data.get("community")
            threat_score = data.get("threat_score")

            # Size: base 15, scaled by centrality (max ~50)
            size = 15 + centrality * 200

            # Color
            if color_by == "threat" and node_type == "email_address" and threat_score is not None:
                color = self._color_by_threat(threat_score)
            elif color_by == "community" and community_id is not None:
                color = COMMUNITY_COLORS[community_id % len(COMMUNITY_COLORS)]
            else:
                color = NODE_TYPE_COLORS.get(node_type, "#bdc3c7")

            # Border for high-threat nodes
            border_color = "#ff0000" if threat_score and threat_score > 70 else color
            border_width = 3 if threat_score and threat_score > 70 else 1

            # Tooltip
            tooltip_parts = [
                f"<b>{label}</b>",
                f"Type: {node_type}",
            ]
            if centrality > 0:
                tooltip_parts.append(f"Centrality: {centrality:.4f}")
            if community_id is not None:
                tooltip_parts.append(f"Community: {community_id}")
            if threat_score is not None:
                tooltip_parts.append(f"Threat Score: {threat_score}/100")

            # Auth results for email nodes
            for auth in ("spf_pass", "dkim_pass", "dmarc_pass"):
                if auth in data and data[auth] is not None:
                    auth_label = auth.replace("_pass", "").upper()
                    status = "✅ PASS" if data[auth] else "❌ FAIL"
                    tooltip_parts.append(f"{auth_label}: {status}")

            tooltip = "<br>".join(tooltip_parts)

            net.add_node(
                node_id,
                label=self._shorten_label(label),
                title=tooltip,
                size=size,
                color={
                    "background": color,
                    "border": border_color,
                    "highlight": {"background": "#ffffff", "border": color},
                },
                borderWidth=border_width,
                shape=NODE_TYPE_SHAPES.get(node_type, "dot"),
                font={"size": 12, "color": "#ffffff"},
            )

        # ── Add edges ──
        for source, target, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type", "unknown")
            edge_color = EDGE_COLORS.get(edge_type, "#7f8c8d")

            # Tooltip for edge
            tooltip_parts = [f"Type: {edge_type}"]
            if "scan_id" in data:
                tooltip_parts.append(f"Scan: {data['scan_id']}")
            if "subject" in data:
                tooltip_parts.append(f"Subject: {data['subject']}")
            if "threat_score" in data and data["threat_score"] is not None:
                tooltip_parts.append(f"Threat: {data['threat_score']}/100")

            net.add_edge(
                source, target,
                title="<br>".join(tooltip_parts),
                color=edge_color,
                width=2 if edge_type == "sent" else 1,
                arrows="to",
                dashes=edge_type in ("belongs_to", "url_hosted_on"),
            )

        # Save
        output = str(Path(output_path).resolve())
        net.save_graph(output)

        # Inject custom CSS for dark theme legend
        self._inject_legend(output)

        return output

    def _shorten_label(self, label: str, max_len: int = 25) -> str:
        """Shorten a label for display, keeping it readable."""
        if len(label) <= max_len:
            return label
        return label[:max_len - 3] + "..."

    def _color_by_threat(self, threat_score: float) -> str:
        """Map a 0-100 threat score to a color from THREAT_COLORS."""
        color = THREAT_COLORS[0][1]
        for threshold, hex_color in THREAT_COLORS:
            if threat_score >= threshold:
                color = hex_color
        return color

    def _inject_legend(self, html_path: str) -> None:
        """Inject a floating legend into the generated HTML."""
        legend_html = """
        <div id="threat-legend" style="
            position: fixed; top: 20px; right: 20px;
            background: rgba(20,20,20,0.9); border: 1px solid #333;
            border-radius: 8px; padding: 16px; color: #fff;
            font-family: 'Segoe UI', sans-serif; font-size: 13px;
            z-index: 9999; min-width: 180px;
        ">
            <div style="font-weight:bold; margin-bottom:10px; font-size:14px;">
                🔍 Node Legend
            </div>
            <div style="margin:4px 0;"><span style="color:#e74c3c;">●</span> Email Address</div>
            <div style="margin:4px 0;"><span style="color:#9b59b6;">◆</span> Domain</div>
            <div style="margin:4px 0;"><span style="color:#f1c40f;">▲</span> IP Address</div>
            <div style="margin:4px 0;"><span style="color:#1abc9c;">■</span> URL</div>
            <hr style="border-color:#333; margin:8px 0;">
            <div style="font-weight:bold; margin-bottom:6px;">Edge Types</div>
            <div style="margin:4px 0;"><span style="color:#e74c3c;">—</span> Sent</div>
            <div style="margin:4px 0;"><span style="color:#f1c40f;">—</span> Originated From</div>
            <div style="margin:4px 0;"><span style="color:#e67e22;">—</span> Same IP</div>
            <div style="margin:4px 0;"><span style="color:#1abc9c;">—</span> Contains URL</div>
            <div style="margin:4px 0;"><span style="color:#95a5a6;">---</span> Belongs To</div>
        </div>
        """
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
            content = content.replace("</body>", legend_html + "\n</body>")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass  # Non-critical — graph still works without legend
