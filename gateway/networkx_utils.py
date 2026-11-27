"""
networkx_utils.py — Fallback graph builder for gateway pipeline orchestrator.
Generates structured NetworkX threat topology exports from individual scans.
"""
from __future__ import annotations
import urllib.parse
from typing import Any, Dict, List


def extract_domain(email_or_url: str) -> str:
    if "@" in email_or_url:
        return email_or_url.split("@")[-1].strip().lower()
    if email_or_url.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(email_or_url)
        return (parsed.hostname or "").lower()
    return email_or_url.strip().lower()


def build_threat_graph_from_scan(
    scan_id: str,
    sender: str,
    recipient: str,
    urls: List[str] | None = None,
    threat_score: int | float = 50,
    verdict: str = "suspicious",
    originating_ip: str | None = None,
) -> Dict[str, Any]:
    urls = urls or []
    nodes = []
    edges = []
    node_ids = set()

    def add_node(nid: str, ntype: str, label: str, score: float | None = None, vdict: str | None = None):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "type": ntype,
                "label": label,
                "community": 0,
                "centrality": 0.5 if ntype == "email_address" else 0.2,
                "threat_score": score,
                "scan_ids": [scan_id] if score is not None else [],
                "auth": {},
                "verdict": vdict,
            })

    # Sender Node
    add_node(sender, "email_address", sender, threat_score, verdict)

    # Sender Domain
    sender_domain = extract_domain(sender)
    if sender_domain:
        s_dom_id = f"domain:{sender_domain}"
        add_node(s_dom_id, "domain", sender_domain)
        edges.append({"source": sender, "target": s_dom_id, "type": "belongs_to"})

    # Recipient Node
    if recipient:
        add_node(recipient, "email_address", recipient)
        edges.append({"source": sender, "target": recipient, "type": "sent"})

        rcpt_domain = extract_domain(recipient)
        if rcpt_domain:
            r_dom_id = f"domain:{rcpt_domain}"
            add_node(r_dom_id, "domain", rcpt_domain)
            edges.append({"source": recipient, "target": r_dom_id, "type": "belongs_to"})

    # Originating IP Node
    if originating_ip:
        ip_id = f"ip:{originating_ip}"
        add_node(ip_id, "ip", originating_ip)
        edges.append({"source": sender, "target": ip_id, "type": "originated_from"})

    # URLs
    for url in urls:
        url_id = f"url:{url}"
        add_node(url_id, "url", url, threat_score, verdict)
        edges.append({"source": sender, "target": url_id, "type": "contains_url"})

        u_dom = extract_domain(url)
        if u_dom and u_dom != sender_domain:
            ud_id = f"domain:{u_dom}"
            add_node(ud_id, "domain", u_dom)
            edges.append({"source": url_id, "target": ud_id, "type": "url_hosted_on"})

    communities = [{
        "community_id": 0,
        "size": len(nodes),
        "risk_level": "critical" if threat_score >= 80 else ("high" if threat_score >= 60 else "medium"),
        "avg_threat_score": threat_score,
        "members": [{"id": n["id"], "type": n["type"]} for n in nodes],
        "top_brokers": [sender],
        "dominant_verdict": verdict,
    }]

    return {
        "nodes": nodes,
        "edges": edges,
        "communities": communities,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "community_count": 1,
            "density": round(len(edges) / max(1, len(nodes) * (len(nodes) - 1)), 4),
        }
    }
