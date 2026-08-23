# System Architecture

## Overview

The Attack Path Analyzer follows a three-tier architecture with a strict
separation between mathematical computation, persistence, and presentation:

```
+---------------------------+         +---------------------------+
|  analytics-dashboard      |  HTTP   |  core-engine              |
|  React 18 + TypeScript    | ------> |  FastAPI + NetworkX       |
|  Vite dev server :5173    |  JSON   |  uvicorn :8000            |
|  Cytoscape.js canvas      | <------ |  Pydantic v2 validation   |
+---------------------------+         +------------+--------------+
                                                   |
                                                   | Bolt (optional)
                                                   v
                                       +---------------------------+
                                       |  Neo4j 5.x                |
                                       |  (:Asset)-[:EXPLOITS]->   |
                                       +---------------------------+
                                                   ^
                                                   | fallback (in-process)
                                       +---------------------------+
                                       |  Deterministic mock       |
                                       |  dataset (seed 42)        |
                                       +---------------------------+
```

## Component Responsibilities

### core-engine (Python backend)

| Module | Responsibility |
| --- | --- |
| `algorithms.py` | Pure graph mathematics: CVSS-to-probability mapping, path probability products, Dijkstra over `-ln(p)` weights, remediation edge ranking. No I/O. |
| `database.py` | Single data-access boundary. Queries Neo4j when configured; otherwise returns the deterministic mock dataset whose schema exactly mirrors the Cypher schema. Converts canonical dictionaries into `networkx.DiGraph`. |
| `models.py` | Pydantic v2 request/response schemas enforcing strict transport validation (`extra="forbid"` on requests). |
| `main.py` | FastAPI application: CORS configuration, endpoint wiring, HTTP error translation. |

### analytics-dashboard (React frontend)

| File | Responsibility |
| --- | --- |
| `src/App.tsx` | State orchestration: fetches topology and metrics on mount, owns dropdown selections, triggers concurrent path and remediation analyses. |
| `src/components/GraphCanvas.tsx` | Cytoscape.js rendering. Colors nodes by asset type, marks crown jewels with a star shape, highlights the critical path in crimson with a pulse animation. |
| `src/components/RiskMetrics.tsx` | Displays P(Path) as a percentage, per-edge probability breakdown, aggregate path counts, and top vulnerable assets. |
| `src/components/RemediationPanel.tsx` | Renders ranked mitigation recommendations naming the specific patch or configuration change per edge. |
| `src/types.ts` | TypeScript interfaces mirroring the Pydantic schemas one-to-one. |

### database-schema (Neo4j)

- `schema.cypher`: uniqueness constraint on `Asset.id`, existence constraint,
  indexes on `is_entry_point`, `is_crown_jewel`, and relationship `cve_id`.
- `seed.cypher`: the demonstration topology, structurally identical to the
  mock dataset.

## Data Flow

### Primary flow (Neo4j configured and reachable)

1. Browser loads the dashboard from the Vite dev server at
   `http://localhost:5173`.
2. `App.tsx` issues `GET /api/graph` and `GET /api/analytics/metrics` to
   `http://localhost:8000`.
3. FastAPI validates routing, calls `database.load_graph_data()`.
4. The driver opens a Bolt session, runs one `MATCH (a:Asset)-[r:EXPLOITS]->(b:Asset)`
   projection query, and materializes canonical node/edge dictionaries.
5. `build_networkx_graph()` converts them to a `networkx.DiGraph`; algorithm
   functions operate on this in-memory structure.
6. Responses serialize through Pydantic models; the browser renders the
   topology and metrics.

### Fallback flow (Neo4j absent or unreachable)

1. `load_graph_data()` checks for `NEO4J_PASSWORD` in the environment.
2. If unset, it immediately returns the mock dataset. If set but the driver
   raises any exception (connection refused, authentication failure, missing
   schema), the exception is caught and the same mock dataset is returned.
3. The mock generator re-seeds the PRNG with `random.seed(42)` on every call,
   guaranteeing byte-identical output across restarts.
4. Because the mock dataset's node labels, relationship properties, and CVSS
   fields exactly mirror `schema.cypher` / `seed.cypher`, no downstream code
   distinguishes the two sources. The `/api/health` endpoint reports which
   backend served the request for transparency.

This design guarantees that every academic demonstration, test run, and CI
execution is reproducible without external infrastructure.

## The CORS Boundary

Browsers enforce the same-origin policy: JavaScript served from
`http://localhost:5173` cannot read responses from `http://localhost:8000`
unless the backend explicitly grants permission via Cross-Origin Resource
Sharing headers.

`core-engine/main.py` configures FastAPI's `CORSMiddleware` with:

```python
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```

For non-simple requests (the dashboard's `POST` calls carry a
`Content-Type: application/json` header), the browser first sends an
`OPTIONS` preflight; the middleware answers it with
`Access-Control-Allow-Origin: http://localhost:5173`, after which the actual
request proceeds. Without this explicit grant every dashboard fetch would be
blocked client-side regardless of backend health.

## API Contract

| Method | Path | Request body | Response model |
| --- | --- | --- | --- |
| GET | `/api/graph` | none | `GraphResponse` |
| POST | `/api/analyze/shortest-path` | `{source_id, target_id}` | `ShortestPathResponse` |
| GET | `/api/analytics/metrics` | none | `MetricsResponse` |
| POST | `/api/remediation/suggest` | `{source_id, target_id}` | `RemediationResponse` |
| GET | `/api/health` | none | `{status, data_source}` |

Error semantics:

- `404`: an asset ID does not exist in the graph.
- `422`: Pydantic validation failure, or no attack path exists between the
  requested endpoints.
- `500`: unexpected engine faults (not expected under normal operation).

## Design Decisions

1. **Algorithms are pure functions over `networkx.DiGraph`.** This decouples
   mathematics from both persistence and transport, enabling the unittest
   suite to validate the framework on hand-built toy graphs without mocks of
   Neo4j or HTTP.
2. **Single data-access boundary.** All endpoints obtain topology exclusively
   through `database.load_graph_data()`, so the fallback mechanism is a
   property of the layer rather than scattered conditionals.
3. **Schema mirroring.** The mock dataset duplicates the Cypher schema
   deliberately: structural interchangeability means a demonstration behaves
   identically whether or not the database is running.
4. **Strict request validation.** `extra="forbid"` rejects unknown fields,
   catching client/server contract drift at the boundary instead of deep in
   the analysis pipeline.