/*
 * graph_connector.js
 * --------------------------------------------------------------
 * Bridges the frontend's localStorage scan shape (SM.state.scans)
 * to the NetworkX graph module's ScanResult contract.
 *
 * The NetworkX module expects every scan to have at least:
 *   scan_id, sender, recipients, subject, originating_ip, urls,
 *   threat_score, verdict, spf_pass, dkim_pass, dmarc_pass.
 *
 * The frontend's local scan shape is different — it stores the
 * raw EML fields, a `risk` label (LOW/MEDIUM/HIGH/CRITICAL), a
 * `score` (0-100), and parsed indicators (ips, urls, hash).
 * This file converts between the two.
 *
 * No dependencies. Pure functions. Exposes `GraphConnector` on
 * `window` so script.js can call it without a bundler.
 * --------------------------------------------------------------
 */

(function () {
  "use strict";

  /** Map frontend risk label → graph module verdict. */
  const RISK_TO_VERDICT = {
    LOW: "clean",
    MEDIUM: "suspicious",
    HIGH: "phishing",
    CRITICAL: "phishing",
  };

  /** Map frontend SPF/DKIM/DMARC strings → booleans. */
  function authToBool(v) {
    if (v === true || v === false) return v;
    if (typeof v !== "string") return null;
    const s = v.toUpperCase();
    if (s === "PASS") return true;
    if (s === "FAIL" || s === "SOFTFAIL") return false;
    return null; // UNKNOWN / NEUTRAL / etc. → leave null
  }

  /** Split "Name <addr@x>" or plain "addr@x" into the bare address. */
  function bareAddress(s) {
    if (!s) return null;
    const m = String(s).match(/<([^>]+)>|([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/);
    return m ? (m[1] || m[2]) : String(s);
  }

  /**
   * Frontend scans store time as a local clock string ("20:42:18")
   * which `new Date(...)` cannot parse. Try a few shapes and fall
   * back to "now" if nothing works.
   */
  function parseFrontendTime(t) {
    if (!t) return new Date().toISOString();
    const direct = new Date(t);
    if (!isNaN(direct.getTime())) return direct.toISOString();
    const m = String(t).match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
    if (m) {
      const d = new Date();
      d.setHours(+m[1], +m[2], +(m[3] || 0), 0);
      return d.toISOString();
    }
    return new Date().toISOString();
  }

  /** Convert one frontend scan record into a NetworkX ScanResult. */
  function toScanResult(scan) {
    if (!scan || typeof scan !== "object") {
      throw new Error("GraphConnector: scan must be an object");
    }
    const scan_id = scan.id || scan.scan_id;
    if (!scan_id) {
      throw new Error("GraphConnector: scan is missing id");
    }

    const sender = bareAddress(scan.from) || scan.sender || "";
    if (!sender) {
      throw new Error("GraphConnector: scan has no usable sender");
    }

    // Recipients: frontend stores them as a single "to" string or "recipient"
    const toField = scan.to || scan.recipient || (Array.isArray(scan.recipients) ? scan.recipients.join(",") : "");
    const recipients = String(toField)
      .split(/[,;]+/)
      .map((s) => bareAddress(s.trim()))
      .filter(Boolean);

    // First IP = originating IP. The frontend stores all IPs in `ips` or `indicators.ips`.
    const ips = Array.isArray(scan.ips) ? scan.ips : (scan.indicators?.ips || []);
    const originating_ip = ips.length ? ips[0] : null;

    const urls = Array.isArray(scan.urls) ? scan.urls.slice() : (scan.indicators?.urls ? scan.indicators.urls.slice() : []);
    const score = typeof scan.score === "number" ? scan.score : (typeof scan.fraud_score === "number" ? scan.fraud_score : null);
    const risk = scan.risk || scan.risk_level || "";

    return {
      scan_id: scan_id,
      sender,
      recipients,
      subject: scan.subject || "",
      originating_ip,
      urls: urls,
      threat_score: score,
      verdict: RISK_TO_VERDICT[String(risk).toUpperCase()] || scan.verdict || null,
      spf_pass: authToBool(scan.spf || scan.forensic_breakdown?.spf),
      dkim_pass: authToBool(scan.dkim || scan.forensic_breakdown?.dkim),
      dmarc_pass: authToBool(scan.dmarc || scan.forensic_breakdown?.dmarc),
      ml_features: {
        frontend_classification: scan.classification || null,
        frontend_reasons: Array.isArray(scan.reasons)
          ? scan.reasons.slice()
          : [],
        frontend_hash: scan.hash || scan.sha256 || null,
      },
      timestamp: parseFrontendTime(scan.time || scan.timestamp),
    };
  }

  /** Convert all scans currently in localStorage. Skips invalid ones. */
  function allScanResults() {
    const scans = (window.SM && window.SM.state && window.SM.state.scans) || [];
    const out = [];
    const errors = [];
    for (const s of scans) {
      try {
        out.push(toScanResult(s));
      } catch (e) {
        errors.push({ id: s && s.id, error: e.message });
      }
    }
    return { scan_results: out, errors };
  }

  /** Post a single scan to the backend's /api/scans endpoint. */
  async function postScan(scan, endpoint = "/api/scans") {
    const result = toScanResult(scan);
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(result),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `GraphConnector: POST ${endpoint} failed (${res.status}) ${text}`
      );
    }
    return res.json().catch(() => ({}));
  }

  /** Fetch the graph export JSON from the backend. */
  async function getGraph(endpoint = "/api/graph") {
    const res = await fetch(endpoint);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `GraphConnector: GET ${endpoint} failed (${res.status}) ${text}`
      );
    }
    return res.json();
  }

  // ────────────────────────────────────────────────────────────
  // Browser-side graph builder (mirrors networkx_module shape)
  // ────────────────────────────────────────────────────────────
  //
  // The Python side builds a MultiDiGraph of:
  //   nodes: email_address, domain, ip, url
  //   edges: sent, belongs_to, originated_from, contains_url,
  //          url_hosted_on, same_ip
  //
  // We rebuild the same shape in JS so the frontend can render a
  // real graph without waiting on the backend. The backend's
  // `api_export.js` produces the same shape later — these two are
  // designed to be drop-in compatible.

  const NODE_COLORS = {
    email_address: "#e74c3c",
    domain: "#9b59b6",
    ip: "#f1c40f",
    url: "#1abc9c",
  };
  const NODE_SHAPES = {
    email_address: "circle",
    domain: "diamond",
    ip: "triangle",
    url: "square",
  };
  const EDGE_COLORS = {
    sent: "#e74c3c",
    belongs_to: "#95a5a6",
    originated_from: "#f1c40f",
    contains_url: "#1abc9c",
    url_hosted_on: "#9b59b6",
    same_ip: "#e67e22",
  };

  function _domainOf(addr) {
    if (!addr) return null;
    const a = String(addr);
    const i = a.lastIndexOf("@");
    return i >= 0 ? a.slice(i + 1).toLowerCase() : null;
  }

  function _urlDomain(u) {
    if (!u) return null;
    try {
      return new URL(u).hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  function _shortHash(s, n = 10) {
    // Lightweight deterministic id for long URLs (matches Python md5 prefix)
    let h = 0;
    for (let i = 0; i < s.length; i++) {
      h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    }
    return Math.abs(h).toString(16).padStart(8, "0").slice(0, n);
  }

  /**
   * Build a frontend graph (nodes + edges) from SM.state.scans.
   * Returns the same shape networkx_module.api_export.build_api_export
   * produces: { nodes: [...], edges: [...], stats: {...} }.
   */
  function buildGraph() {
    const scans = (window.SM && window.SM.state && window.SM.state.scans) || [];
    const nodes = new Map(); // id -> {id, type, label, ...}
    const edges = [];
    const ipSenders = new Map(); // ip -> [senderId, ...]

    function upsert(id, type, label, extras) {
      if (nodes.has(id)) {
        Object.assign(nodes.get(id), extras || {});
        return;
      }
      nodes.set(id, Object.assign({ id, type, label }, extras || {}));
    }
    function edge(s, t, type, extras) {
      edges.push(Object.assign({ source: s, target: t, type }, extras || {}));
    }

    for (const scan of scans) {
      const rawSender = scan.from || scan.sender || "";
      const sender = bareAddress(rawSender);
      if (!sender) continue;
      const sid = sender.toLowerCase();
      const sdomain = _domainOf(sender);
      const scanId = scan.id || scan.scan_id || `scan_${Math.random().toString(36).slice(2, 8)}`;
      const threatScore = typeof scan.score === "number" ? scan.score : (typeof scan.fraud_score === "number" ? scan.fraud_score : null);
      const risk = scan.risk || scan.risk_level || "LOW";

      upsert(sid, "email_address", sender, {
        scan_ids: [scanId],
        threat_score: threatScore,
        risk: risk,
      });
      if (sdomain) {
        upsert("domain:" + sdomain, "domain", sdomain);
        edge(sid, "domain:" + sdomain, "belongs_to", { scan_id: scanId });
      }

      // Recipients
      const toField = scan.to || scan.recipient || "";
      for (const r of String(toField).split(/[,;]+/)) {
        const rcpt = bareAddress(r.trim());
        if (!rcpt) continue;
        const rid = rcpt.toLowerCase();
        upsert(rid, "email_address", rcpt);
        edge(sid, rid, "sent", {
          scan_id: scanId,
          subject: scan.subject || "",
          threat_score: threatScore,
        });
        const rd = _domainOf(rcpt);
        if (rd) {
          upsert("domain:" + rd, "domain", rd);
          edge(rid, "domain:" + rd, "belongs_to", { scan_id: scanId });
        }
      }

      // Originating IP & Indicators
      const ips = Array.isArray(scan.ips) ? scan.ips : (scan.indicators?.ips || []);
      if (ips.length) {
        for (const ip of ips) {
          if (!ip) continue;
          const ipId = "ip:" + ip;
          upsert(ipId, "ip", ip);
          edge(sid, ipId, "originated_from", { scan_id: scanId });

          if (!ipSenders.has(ip)) ipSenders.set(ip, new Set());
          const set = ipSenders.get(ip);
          for (const other of set) {
            edge(sid, other, "same_ip", { ip });
          }
          set.add(sid);
        }
      }

      // URLs
      const urls = Array.isArray(scan.urls) ? scan.urls : (scan.indicators?.urls || []);
      if (urls.length) {
        for (const u of urls) {
          if (!u) continue;
          const urlId = "url:" + _shortHash(u);
          upsert(urlId, "url", u.length > 60 ? u.slice(0, 57) + "..." : u, {
            full_url: u,
          });
          edge(sid, urlId, "contains_url", { scan_id: scanId });
          const ud = _urlDomain(u);
          if (ud) {
            upsert("domain:" + ud, "domain", ud);
            edge(urlId, "domain:" + ud, "url_hosted_on", { scan_id: scanId });
          }
        }
      }

      // Auth flags
      const node = nodes.get(sid);
      if (node) {
        node.spf = scan.spf || scan.forensic_breakdown?.spf || null;
        node.dkim = scan.dkim || scan.forensic_breakdown?.dkim || null;
        node.dmarc = scan.dmarc || scan.forensic_breakdown?.dmarc || null;
      }
    }

    // Stats
    const typeCounts = {};
    for (const n of nodes.values())
      typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
    const edgeTypeCounts = {};
    for (const e of edges)
      edgeTypeCounts[e.type] = (edgeTypeCounts[e.type] || 0) + 1;

    return {
      nodes: Array.from(nodes.values()),
      edges,
      stats: {
        total_nodes: nodes.size,
        total_edges: edges.length,
        node_types: typeCounts,
        edge_types: edgeTypeCounts,
      },
    };
  }

  // ────────────────────────────────────────────────────────────
  // Community detection + risk classification (browser-side)
  // ────────────────────────────────────────────────────────────
  //
  // The Python side runs python-louvain on the undirected graph
  // projection. We mirror that here with a label-propagation pass
  // on the undirected simple graph — same goal (densely connected
  // groups of nodes), zero dependencies, deterministic enough for
  // a UI hint. The backend's real Louvain result, when available,
  // should win over this one.

  /** Undirected adjacency with weights (edge multiplicities). */
  function _undirectedAdjacency(graph) {
    const adj = new Map();
    const ensure = (id) => {
      if (!adj.has(id)) adj.set(id, new Map());
      return adj.get(id);
    };
    for (const n of graph.nodes) ensure(n.id);
    for (const e of graph.edges) {
      ensure(e.source).set(e.target, (ensure(e.source).get(e.target) || 0) + 1);
      ensure(e.target).set(e.source, (ensure(e.target).get(e.source) || 0) + 1);
    }
    return adj;
  }

  /** Betweenness centrality on the undirected projection (Brandes). */
  function _betweenness(adj) {
    const ids = Array.from(adj.keys());
    const cb = new Map();
    for (const id of ids) cb.set(id, 0);
    for (const s of ids) {
      const stack = [];
      const pred = new Map();
      const sigma = new Map();
      const dist = new Map();
      for (const id of ids) {
        pred.set(id, []);
        sigma.set(id, 0);
        dist.set(id, -1);
      }
      sigma.set(s, 1);
      dist.set(s, 0);
      const queue = [s];
      while (queue.length) {
        const v = queue.shift();
        stack.push(v);
        for (const [w] of adj.get(v)) {
          if (dist.get(w) < 0) {
            dist.set(w, dist.get(v) + 1);
            queue.push(w);
          }
          if (dist.get(w) === dist.get(v) + 1) {
            sigma.set(w, sigma.get(w) + sigma.get(v));
            pred.get(w).push(v);
          }
        }
      }
      const delta = new Map();
      for (const id of ids) delta.set(id, 0);
      while (stack.length) {
        const w = stack.pop();
        for (const v of pred.get(w)) {
          delta.set(
            v,
            delta.get(v) + (sigma.get(v) / sigma.get(w)) * (1 + delta.get(w))
          );
        }
        if (w !== s) cb.set(w, cb.get(w) + delta.get(w));
      }
    }
    // Normalize to [0, 1] for undirected graphs (divide by 2)
    const max = Math.max(...cb.values(), 1e-9);
    for (const [k, v] of cb) cb.set(k, v / max / 2);
    return cb;
  }

  /**
   * Label propagation: each node adopts the most common label among
   * its weighted neighbors; tie-break on the current label so the
   * algorithm is stable across runs. We seed email_address nodes
   * with their own id so the "you are your own community" effect
   * only happens for isolated senders.
   */
  function _labelPropagation(adj, maxIter = 20) {
    const labels = new Map();
    for (const id of adj.keys()) labels.set(id, id);

    for (let iter = 0; iter < maxIter; iter++) {
      let changed = false;
      const ids = Array.from(adj.keys());
      // Deterministic shuffle order based on id
      ids.sort();
      for (const id of ids) {
        const neighbors = adj.get(id);
        if (!neighbors.size) continue;
        const counts = new Map();
        for (const [nid, w] of neighbors) {
          const lbl = labels.get(nid);
          counts.set(lbl, (counts.get(lbl) || 0) + w);
        }
        // Pick the label with the highest weight
        let best = labels.get(id);
        let bestW = -1;
        for (const [lbl, w] of counts) {
          if (w > bestW || (w === bestW && lbl < best)) {
            best = lbl;
            bestW = w;
          }
        }
        if (best !== labels.get(id)) {
          labels.set(id, best);
          changed = true;
        }
      }
      if (!changed) break;
    }
    return labels;
  }

  /** Map frontend risk label → numeric score for averaging. */
  function _riskToNum(r) {
    return ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 })[String(r || "").toUpperCase()] || 0;
  }

  /** Classify a community's risk (mirrors classify_risk in analysis.py). */
  function _classifyRisk(avgThreat, size) {
    if (avgThreat == null) {
      return size > 5 ? "medium" : "low";
    }
    let level = "low";
    if (avgThreat >= 80) level = "critical";
    else if (avgThreat >= 60) level = "high";
    else if (avgThreat >= 30) level = "medium";
    if (size <= 3 && avgThreat >= 70 && level !== "critical") level = "critical";
    return level;
  }

  /**
   * Detect communities in a graph produced by `buildGraph()`.
   * Returns an object with the same shape as the Python
   * `api_export.build_api_export` analysis section:
   *
   *   {
   *     num_communities: int,
   *     communities: [
   *       { community_id, size, members, top_brokers,
   *         avg_threat_score, domains, ips, risk_level, scan_ids },
   *       ...
   *     ],
   *     top_brokers: [{ id, type, label, centrality, community }, ...]
   *   }
   */
  function detectCommunities(graph) {
    if (!graph || !graph.nodes.length) {
      return { num_communities: 0, communities: [], top_brokers: [] };
    }
    const adj = _undirectedAdjacency(graph);
    const labels = _labelPropagation(adj);
    const betweenness = _betweenness(adj);

    // Group node ids by label, remap to integer community ids
    const groups = new Map();
    for (const [nid, lbl] of labels) {
      if (!groups.has(lbl)) groups.set(lbl, []);
      groups.get(lbl).push(nid);
    }
    const labelToId = new Map();
    let nextId = 0;
    const groupsArr = Array.from(groups.entries())
      .map(([lbl, ids]) => {
        if (!labelToId.has(lbl)) labelToId.set(lbl, nextId++);
        return { id: labelToId.get(lbl), lbl, members: ids };
      })
      // Largest first so the summary list is intuitive
      .sort((a, b) => b.members.length - a.members.length);

    // Build per-community summary
    const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
    const communities = groupsArr.map((g, idx) => {
      const memberNodes = g.members.map((id) => nodeById.get(id)).filter(Boolean);
      const threatScores = [];
      const domains = new Set();
      const ips = new Set();
      const scanIds = new Set();
      const memberDetails = memberNodes
        .map((n) => ({
          id: n.id,
          type: n.type,
          label: n.label,
          centrality: betweenness.get(n.id) || 0,
          community: idx,
        }))
        .sort((a, b) => b.centrality - a.centrality);

      for (const n of memberNodes) {
        if (n.type === "email_address" && typeof n.threat_score === "number") {
          threatScores.push(n.threat_score);
        }
        if (n.type === "email_address" && n.risk) {
          // Use the highest risk-level number if no score
          if (!threatScores.length) threatScores.push(_riskToNum(n.risk) * 25);
        }
        if (n.type === "domain") domains.add(n.label);
        if (n.type === "ip") ips.add(n.label);
        if (Array.isArray(n.scan_ids)) n.scan_ids.forEach((s) => scanIds.add(s));
      }
      const topBrokers = memberDetails.filter((m) => m.centrality > 0).slice(0, 3);
      const avgThreat = threatScores.length
        ? Math.round((threatScores.reduce((a, b) => a + b, 0) / threatScores.length) * 10) / 10
        : null;
      return {
        community_id: idx,
        size: g.members.length,
        members: memberDetails,
        top_brokers: topBrokers,
        avg_threat_score: avgThreat,
        domains: Array.from(domains).sort(),
        ips: Array.from(ips).sort(),
        scan_ids: Array.from(scanIds),
        risk_level: _classifyRisk(avgThreat, g.members.length),
      };
    });

    // Sort by risk priority then size (matches Python analyzer)
    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    communities.sort((a, b) => {
      const r = (riskOrder[a.risk_level] || 4) - (riskOrder[b.risk_level] || 4);
      if (r !== 0) return r;
      return b.size - a.size;
    });

    // Global top brokers
    const topBrokers = graph.nodes
      .map((n) => ({
        id: n.id,
        type: n.type,
        label: n.label,
        centrality: betweenness.get(n.id) || 0,
        community: labels.get(n.id),
        threat_score: n.threat_score,
      }))
      .filter((b) => b.centrality > 0)
      .sort((a, b) => b.centrality - a.centrality)
      .slice(0, 10);

    return {
      num_communities: communities.length,
      communities,
      top_brokers: topBrokers,
    };
  }

  window.GraphConnector = {
    toScanResult,
    allScanResults,
    postScan,
    getGraph,
    buildGraph,
    detectCommunities,
    NODE_COLORS,
    NODE_SHAPES,
    EDGE_COLORS,
  };
})();
