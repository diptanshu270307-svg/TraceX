"""
graph_builder.py — Constructs a NetworkX MultiDiGraph from parsed email data.

Node types:
  - email_address  (sender/receiver addresses)
  - domain         (extracted from email addresses and URLs)
  - ip             (originating IPs from email headers)
  - url            (URLs found in email body)

Edge types:
  - sent           (email_address → email_address)
  - belongs_to     (email_address → domain)
  - originated_from (email_address → ip)
  - contains_url   (email_address → url)
  - url_hosted_on  (url → domain)
  - same_ip        (email_address ↔ email_address, if same originating IP)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx


@dataclass
class EmailRecord:
    """Parsed email metadata fed into the graph builder.

    Attributes:
        scan_id:       Unique scan identifier.
        sender:        Sender email address (e.g. "attacker@evil.com").
        recipients:    List of recipient email addresses.
        subject:       Email subject line.
        originating_ip: IP from the earliest Received header (optional).
        urls:          URLs extracted from the email body.
        threat_score:  ML-assigned threat probability 0-100 (optional).
        spf_pass:      Whether SPF authentication passed (optional).
        dkim_pass:     Whether DKIM authentication passed (optional).
        dmarc_pass:    Whether DMARC authentication passed (optional).
    """

    scan_id: str
    sender: str
    recipients: list[str]
    subject: str = ""
    originating_ip: Optional[str] = None
    urls: list[str] = field(default_factory=list)
    threat_score: Optional[float] = None
    spf_pass: Optional[bool] = None
    dkim_pass: Optional[bool] = None
    dmarc_pass: Optional[bool] = None


def _extract_domain(email_address: str) -> Optional[str]:
    """Extract domain from an email address like 'user@domain.com'."""
    if "@" in email_address:
        return email_address.split("@", 1)[1].lower().strip()
    return None


def _extract_url_domain(url: str) -> Optional[str]:
    """Extract domain from a URL like 'https://evil.com/phish'."""
    url = url.lower().strip()
    for prefix in ("https://", "http://", "//"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    # Take everything before the first / or ? or #
    domain = url.split("/")[0].split("?")[0].split("#")[0]
    # Remove port if present
    domain = domain.split(":")[0]
    return domain if domain else None


class ThreatGraphBuilder:
    """Builds a NetworkX MultiDiGraph from a list of EmailRecord objects.

    Usage:
        builder = ThreatGraphBuilder()
        builder.add_email(email_record_1)
        builder.add_email(email_record_2)
        graph = builder.get_graph()
    """

    def __init__(self):
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._ip_to_senders: dict[str, set[str]] = {}

    def add_email(self, record: EmailRecord) -> None:
        """Add a single email record to the graph."""
        sender = record.sender.lower().strip()
        sender_domain = _extract_domain(sender)

        # ── Sender node ──
        self._add_node(
            node_id=sender,
            node_type="email_address",
            label=sender,
            scan_ids=[record.scan_id],
            threat_score=record.threat_score,
            is_sender=True,
        )

        # ── Sender domain node ──
        if sender_domain:
            self._add_node(
                node_id=f"domain:{sender_domain}",
                node_type="domain",
                label=sender_domain,
            )
            self._add_edge(
                sender, f"domain:{sender_domain}",
                edge_type="belongs_to",
                scan_id=record.scan_id,
            )

        # ── Recipient nodes + sent edges ──
        for recipient in record.recipients:
            recipient = recipient.lower().strip()
            self._add_node(
                node_id=recipient,
                node_type="email_address",
                label=recipient,
                is_sender=False,
            )
            self._add_edge(
                sender, recipient,
                edge_type="sent",
                scan_id=record.scan_id,
                subject=record.subject,
                threat_score=record.threat_score,
            )

            # Recipient domain
            rcpt_domain = _extract_domain(recipient)
            if rcpt_domain:
                self._add_node(
                    node_id=f"domain:{rcpt_domain}",
                    node_type="domain",
                    label=rcpt_domain,
                )
                self._add_edge(
                    recipient, f"domain:{rcpt_domain}",
                    edge_type="belongs_to",
                    scan_id=record.scan_id,
                )

        # ── Originating IP node ──
        if record.originating_ip:
            ip = record.originating_ip.strip()
            ip_id = f"ip:{ip}"
            self._add_node(
                node_id=ip_id,
                node_type="ip",
                label=ip,
            )
            self._add_edge(
                sender, ip_id,
                edge_type="originated_from",
                scan_id=record.scan_id,
            )

            # Track senders per IP for same_ip edges
            if ip not in self._ip_to_senders:
                self._ip_to_senders[ip] = set()
            self._ip_to_senders[ip].add(sender)

            # Add same_ip edges between senders sharing this IP
            for other_sender in self._ip_to_senders[ip]:
                if other_sender != sender:
                    self._add_edge(
                        sender, other_sender,
                        edge_type="same_ip",
                        ip=ip,
                    )

        # ── URL nodes ──
        for url in record.urls:
            url_clean = url.strip()
            # Use a hash-based ID to keep node IDs short for long URLs
            url_hash = hashlib.md5(url_clean.encode()).hexdigest()[:10]
            url_id = f"url:{url_hash}"
            self._add_node(
                node_id=url_id,
                node_type="url",
                label=url_clean if len(url_clean) <= 60 else url_clean[:57] + "...",
                full_url=url_clean,
            )
            self._add_edge(
                sender, url_id,
                edge_type="contains_url",
                scan_id=record.scan_id,
            )

            # URL → domain edge
            url_domain = _extract_url_domain(url_clean)
            if url_domain:
                domain_id = f"domain:{url_domain}"
                self._add_node(
                    node_id=domain_id,
                    node_type="domain",
                    label=url_domain,
                )
                self._add_edge(
                    url_id, domain_id,
                    edge_type="url_hosted_on",
                    scan_id=record.scan_id,
                )

        # ── Store authentication results on sender node ──
        if any(v is not None for v in [record.spf_pass, record.dkim_pass, record.dmarc_pass]):
            self.graph.nodes[sender]["spf_pass"] = record.spf_pass
            self.graph.nodes[sender]["dkim_pass"] = record.dkim_pass
            self.graph.nodes[sender]["dmarc_pass"] = record.dmarc_pass

    def add_emails(self, records: list[EmailRecord]) -> None:
        """Add multiple email records to the graph."""
        for record in records:
            self.add_email(record)

    def get_graph(self) -> nx.MultiDiGraph:
        """Return the constructed MultiDiGraph."""
        return self.graph

    def get_stats(self) -> dict:
        """Return basic graph statistics."""
        node_types: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            t = data.get("node_type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1

        edge_types: dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            t = data.get("edge_type", "unknown")
            edge_types[t] = edge_types.get(t, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": node_types,
            "edge_types": edge_types,
        }

    # ── Internal helpers ──

    def _add_node(self, node_id: str, node_type: str, label: str, **kwargs) -> None:
        """Add a node, merging attributes if it already exists."""
        if self.graph.has_node(node_id):
            existing = self.graph.nodes[node_id]
            # Merge scan_ids lists
            if "scan_ids" in kwargs and "scan_ids" in existing:
                existing_ids = existing["scan_ids"]
                for sid in kwargs["scan_ids"]:
                    if sid not in existing_ids:
                        existing_ids.append(sid)
                del kwargs["scan_ids"]
            existing.update(kwargs)
        else:
            self.graph.add_node(
                node_id,
                node_type=node_type,
                label=label,
                **kwargs,
            )

    def _add_edge(self, source: str, target: str, edge_type: str, **kwargs) -> None:
        """Add a directed edge (allows parallel edges via MultiDiGraph)."""
        self.graph.add_edge(
            source, target,
            edge_type=edge_type,
            **kwargs,
        )
