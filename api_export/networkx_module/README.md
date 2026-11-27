# TraceX — NetworkX Graph Intelligence Module

This module is the **graph side of TraceX**. It ingests ML pipeline scan
results, builds a threat graph, runs community + centrality analysis,
persists everything to PostgreSQL, and emits the JSON the FastAPI/React
frontend consumes.

## Quick start

```bash
cd networkx_module
pip install -r requirements.txt
python -m networkx_module.demo       # from the parent directory
# OR
python demo.py                        # from inside networkx_module/
```

Open `output/threat_graph.html` in a browser.

## Module map

| File              | Purpose                                                  |
| ----------------- | -------------------------------------------------------- |
| `graph_builder.py`| Build the `nx.MultiDiGraph` (nodes: emails, domains, IPs, URLs) |
| `analysis.py`     | Louvain community detection + betweenness centrality + risk classification |
| `models.py`       | Shared dataclasses + DB-row converters                  |
| `db.py`           | PostgreSQL persistence layer (psycopg2)                 |
| `ml_bridge.py`    | One-shot ML-pipeline → graph → analysis entry point     |
| `api_export.py`   | Graph → JSON wire format for FastAPI/React              |
| `visualizer.py`   | Interactive pyvis HTML rendering                        |
| `demo.py`         | End-to-end working reference                            |
| `tests/`          | Contract tests (12 tests, run with `python -m unittest`) |

## Data contracts (cross-team)

### 1. ML pipeline → graph module

`ScanResult` (see `models.py`). A dict matching this shape is what
`ml_bridge.process_scans` consumes. Required fields: `scan_id`, `sender`,
`recipients`. Everything else is optional.

```json
{
  "scan_id": "scan-001",
  "sender": "phisher@evil.com",
  "recipients": ["victim@corp.com"],
  "subject": "Urgent",
  "originating_ip": "185.220.101.42",
  "urls": ["https://evil.com/x"],
  "threat_score": 92.5,
  "verdict": "phishing",
  "spf_pass": false, "dkim_pass": false, "dmarc_pass": false,
  "ml_features": { "levenshtein_score": 0.91 },
  "timestamp": "2026-09-07T08:15:00Z"
}
```

### 2. Graph module → PostgreSQL

`models.build_persistence_payload(graph, analysis)` returns
`(list[GraphNode], list[GraphEdge], list[CommunityRecord])` ready to
pass to `GraphDB.save_analysis(...)` (atomic) or the per-table
`save_nodes` / `save_edges` / `save_communities` methods.

Set connection via env vars: `TRACEX_DB_HOST`, `TRACEX_DB_PORT`,
`TRACEX_DB_NAME`, `TRACEX_DB_USER`, `TRACEX_DB_PASSWORD`.

### 3. Graph module → FastAPI/React

`api_export.build_api_export(graph, analysis)` returns the JSON shape
the frontend expects. Top-level keys: `nodes`, `edges`, `communities`,
`top_brokers`, `stats`, `generated_at`. Use
`filter_export_for_community(export, community_id)` to drill into a
single cluster.

## One-line usage from anywhere

```python
from networkx_module import process_scans, build_persistence_payload
from networkx_module import build_api_export
from networkx_module import GraphDB

result = process_scans(scan_dicts_from_ml_pipeline)
nodes, edges, communities = build_persistence_payload(
    result["graph"], result["analysis"]
)

# Persist
db = GraphDB()
db.create_tables()
db.save_analysis(nodes, edges, communities)

# Serve to frontend
api_payload = build_api_export(result["graph"], result["analysis"])
```

## Risk classification

`analysis.classify_risk(avg_threat_score, size)` returns
`low | medium | high | critical`. A small cluster (≤3 nodes) with a
high threat score (≥70) is auto-escalated to **critical** because
that's almost always a single attacker cluster.

## Tests

```bash
cd networkx_module
python -m unittest tests.test_integration -v
```

12 tests pin the cross-module contract. They will catch regressions
that would break the ML, PostgreSQL, or FastAPI sides.
