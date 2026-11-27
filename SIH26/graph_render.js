/*
 * graph_render.js
 * --------------------------------------------------------------
 * Renders the frontend's graph (built by GraphConnector.buildGraph)
 * as an interactive SVG. No external libs — same look-and-feel
 * as the existing static mock, but driven by real data.
 *
 * Exports `GraphRender` on `window` with:
 *   renderSvg(graphData, onNodeClick) → SVG string
 *   summarizeEntity(graphData, nodeId) → { type, label, neighbors }
 * --------------------------------------------------------------
 */

(function () {
  "use strict";

  const VB_W = 700;
  const VB_H = 450;
  const CENTER = { x: VB_W / 2, y: VB_H / 2 };
  const RADIUS_RING = 140;
  const CENTER_NODES = new Set(["email_address"]); // ring layout for everyone

  // Type radius for the rendering ring
  function _typeRadius(type) {
    if (type === "email_address") return 0; // sits at center cluster
    if (type === "domain") return 90;
    if (type === "ip") return 160;
    if (type === "url") return 210;
    return 110;
  }

  function _short(s, n = 18) {
    if (!s) return "";
    s = String(s);
    return s.length <= n ? s : s.slice(0, n - 1) + "…";
  }

  function _neighbors(graph, id) {
    const out = [];
    for (const e of graph.edges) {
      if (e.source === id) out.push({ dir: "out", edge: e });
      else if (e.target === id) out.push({ dir: "in", edge: e });
    }
    return out;
  }

  const DEFAULT_NODE_COLORS = {
    email_address: "#e74c3c",
    domain: "#9b59b6",
    ip: "#f1c40f",
    url: "#1abc9c",
    attachment_hash: "#e67e22",
  };
  const DEFAULT_EDGE_COLORS = {
    sent: "#e74c3c",
    belongs_to: "#95a5a6",
    originated_from: "#f1c40f",
    contains_url: "#1abc9c",
    url_hosted_on: "#9b59b6",
    same_ip: "#e67e22",
  };

  function _typeColor(type) {
    return (
      (window.GraphConnector && window.GraphConnector.NODE_COLORS && window.GraphConnector.NODE_COLORS[type]) ||
      DEFAULT_NODE_COLORS[type] ||
      "#bdc3c7"
    );
  }
  function _edgeColor(type) {
    return (
      (window.GraphConnector && window.GraphConnector.EDGE_COLORS && window.GraphConnector.EDGE_COLORS[type]) ||
      DEFAULT_EDGE_COLORS[type] ||
      "#7f8c8d"
    );
  }

  /**
   * Place nodes on concentric rings by type. Email addresses sit
   * at the center; domains on the inner ring; IPs on the middle
   * ring; URLs on the outer ring. This gives a clean, readable
   * layout that doesn't need a force simulation.
   */
  function _layout(graph) {
    const buckets = { email_address: [], domain: [], ip: [], url: [] };
    for (const n of graph.nodes) {
      if (buckets[n.type]) buckets[n.type].push(n);
      else buckets[n.type] = [n];
    }
    const pos = new Map();

    function place(list, ring, jitter = 0) {
      const n = list.length;
      if (ring === 0) {
        // Cluster email_address nodes around the center
        const r = Math.min(50, n * 4);
        list.forEach((node, i) => {
          const a = (i / Math.max(n, 1)) * Math.PI * 2;
          pos.set(node.id, {
            x: CENTER.x + Math.cos(a) * r,
            y: CENTER.y + Math.sin(a) * r,
          });
        });
        return;
      }
      list.forEach((node, i) => {
        const a =
          ((i + jitter) / Math.max(n, 1)) * Math.PI * 2 - Math.PI / 2;
        pos.set(node.id, {
          x: CENTER.x + Math.cos(a) * ring,
          y: CENTER.y + Math.sin(a) * ring,
        });
      });
    }
    place(buckets.email_address || [], 0);
    place(buckets.domain || [], 90);
    place(buckets.ip || [], 160);
    place(buckets.url || [], 210);

    for (const [t, list] of Object.entries(buckets)) {
      if (t === "email_address" || t === "domain" || t === "ip" || t === "url") continue;
      place(list, 230);
    }
    return pos;
  }

  function _nodeShape(type, x, y) {
    if (type === "domain") {
      return `<polygon points="${x},${y - 14} ${x + 14},${y} ${x},${y + 14} ${x - 14},${y}"
        fill="#141923" stroke="${_typeColor(type)}" stroke-width="2.5"/>`;
    }
    if (type === "ip") {
      return `<polygon points="${x},${y - 15} ${x + 13},${y + 10} ${x - 13},${y + 10}"
        fill="#141923" stroke="${_typeColor(type)}" stroke-width="2.5"/>`;
    }
    if (type === "url") {
      return `<rect x="${x - 12}" y="${y - 12}" width="24" height="24"
        fill="#141923" stroke="${_typeColor(type)}" stroke-width="2.5"/>`;
    }
    // default: email_address
    return `<circle cx="${x}" cy="${y}" r="14"
      fill="#141923" stroke="${_typeColor(type)}" stroke-width="2.5"/>`;
  }

  function _threatBorder(threatScore) {
    if (typeof threatScore !== "number") return null;
    if (threatScore >= 75) return { color: "#ff0000", width: 3.5 };
    if (threatScore >= 50) return { color: "#e67e22", width: 2.5 };
    return null;
  }

  function _tooltipFor(node) {
    const lines = [
      `<b>${_escape(node.label || node.id)}</b>`,
      `Type: ${node.type}`,
    ];
    if (node.risk) lines.push(`Risk: ${node.risk}`);
    if (typeof node.threat_score === "number")
      lines.push(`Score: ${node.threat_score}/100`);
    if (typeof node.centrality === "number")
      lines.push(`Centrality: ${node.centrality.toFixed(4)}`);
    for (const k of ["spf", "dkim", "dmarc"]) {
      if (node[k]) lines.push(`${k.toUpperCase()}: ${node[k]}`);
    }
    return lines.join("<br>");
  }

  function _escape(s) {
    return String(s ?? "").replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  /**
   * Render graph as an inline SVG string.
   *
   * @param {Object} graph  - { nodes, edges, stats } from GraphConnector.buildGraph
   * @param {Function} onNodeClick - (node) => void
   */
  function renderSvg(graph, onNodeClick) {
    if (!graph || !graph.nodes.length) {
      return `<div class="empty-state" style="height:100%;min-height:380px">
        <strong>No graph data yet</strong>
        <p class="muted">Upload and analyze an .EML file on the Email Analysis page
        to populate the infrastructure graph.</p>
      </div>`;
    }
    const pos = _layout(graph);
    const cbName = "_gcNodeClick";

    const parts = [];
    parts.push(
      `<svg viewBox="0 0 ${VB_W} ${VB_H}" preserveAspectRatio="xMidYMid meet"
            style="width:100%;height:100%">`
    );

    // Edges first so they sit behind nodes
    for (const e of graph.edges) {
      const sId = typeof e.source === "object" ? e.source.id : e.source;
      const tId = typeof e.target === "object" ? e.target.id : e.target;
      const a = pos.get(sId);
      const b = pos.get(tId);
      if (!a || !b) continue;
      const c = _edgeColor(e.type);
      const dashed = e.type === "belongs_to" || e.type === "url_hosted_on";
      const width = e.type === "sent" ? 1.6 : 1.1;
      parts.push(
        `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}"
              stroke="${c}" stroke-width="${width}" ${
          dashed ? 'stroke-dasharray="4 4" ' : ""
        }opacity="0.55"/>`
      );
    }

    // Nodes
    for (const n of graph.nodes) {
      const p = pos.get(n.id);
      if (!p) continue;
      const color = _typeColor(n.type);
      const border = _threatBorder(n.threat_score);
      const shape = _nodeShape(n.type, p.x, p.y);
      const tip = _tooltipFor(n);
      const encodedId = encodeURIComponent(n.id);
      const onClick = onNodeClick
        ? `onclick="window.${cbName} && window.${cbName}('${encodedId}')"`
        : "";
      parts.push(
        `<g class="node-svg" data-node-id="${encodedId}" ${onClick} style="cursor:pointer">
          <title>${tip}</title>
          ${shape}`
      );
      if (border) {
        parts.push(
          `<circle cx="${p.x}" cy="${p.y}" r="${n.type === "email_address" ? 16 : 18}"
                 fill="none" stroke="${border.color}" stroke-width="${border.width}"/>`
        );
      }
      parts.push(
        `<text class="node-title" x="${p.x}" y="${
          p.y + (n.type === "email_address" ? 4 : 4)
        }" text-anchor="middle" font-size="9"
              fill="#e2e8f0" font-weight="700">${_short(
                n.label || n.id,
                n.type === "email_address" ? 22 : 16
              )}</text>`
      );
      parts.push(`</g>`);
    }

    parts.push(`</svg>`);

    if (onNodeClick) {
      // Expose the click handler on window for the inline onclick
      window[cbName] = (encodedId) => {
        const id = decodeURIComponent(encodedId);
        const node = graph.nodes.find((n) => n.id === id);
        if (node) onNodeClick(node, graph);
      };
    }
    return parts.join("");
  }

  /** Summarize a node's role in the graph for the side panel. */
  function summarizeEntity(graph, nodeId) {
    const node = graph.nodes.find((n) => n.id === nodeId);
    if (!node) return null;
    const n = _neighbors(graph, nodeId);
    const counts = { sent: 0, originated_from: 0, contains_url: 0, url_hosted_on: 0, belongs_to: 0, same_ip: 0 };
    const ips = new Set();
    const urls = new Set();
    const senders = new Set();
    for (const { edge } of n) {
      const etype = edge.type;
      counts[etype] = (counts[etype] || 0) + 1;
      if ((etype === "originated_from" || etype === "originates_from") && edge.ip) ips.add(edge.ip);
      if (etype === "contains_url") {
        const tId = typeof edge.target === "object" ? edge.target.id : edge.target;
        const target = graph.nodes.find((x) => x.id === tId);
        if (target && target.full_url) urls.add(target.full_url);
        else if (target && target.label) urls.add(target.label);
      }
      if (etype === "sent" || etype === "sent_email") {
        const sId = typeof edge.source === "object" ? edge.source.id : edge.source;
        senders.add(sId);
      }
    }
    return {
      type: node.type,
      label: node.label || node.id,
      id: node.id,
      risk: node.risk || (node.threat_score >= 80 ? "CRITICAL" : (node.threat_score >= 60 ? "HIGH" : (node.threat_score ? "LOW" : null))),
      threat_score: node.threat_score,
      centrality: node.centrality,
      community: node.community,
      counts,
      ips: Array.from(ips),
      urls: Array.from(urls),
      senders: Array.from(senders),
    };
  }

  window.GraphRender = { renderSvg, summarizeEntity, _escape };
})();
