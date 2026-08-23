# Graph-Theoretic Cyber Attack Path Analysis and Risk Prediction System

An undergraduate final-year engineering project that models enterprise network
assets as a directed graph, computes the most probable multi-stage attack paths
using graph-theoretic algorithms, quantifies risk from CVSS v3.1 exploitability
scores, and ranks remediation actions by their effectiveness at breaking
critical attack paths.

The system consists of three cooperating subsystems:

| Subsystem | Technology | Responsibility |
| --- | --- | --- |
| `core-engine` | Python 3.10+, FastAPI, NetworkX 3.3, Neo4j Driver 5.24 | Graph storage access, risk mathematics, path analysis, REST API |
| `analytics-dashboard` | React 18, TypeScript, Vite, Tailwind CSS, Cytoscape.js | Interactive topology visualization, metrics display, remediation UI |
| `database-schema` | Neo4j Cypher | Graph constraints, indexes, deterministic seed dataset |

## Mathematical Framework Summary

1. **CVSS-to-Probability Mapping.** Each edge's exploitability probability is
   derived from the CVSS v3.1 Exploitability subscore:

   ```
   Exploitability = 8.22 x AttackVector x AttackComplexity x PrivilegesRequired x UserInteraction
   p_i = clamp(Exploitability / 3.887, 0.01, 1.0)
   ```

   The floor of 0.01 prevents mathematically undefined `ln(0)` terms in the
   weight transformation described below.

2. **Path Risk Probability.** The cumulative probability of a path is the
   product of its edge probabilities:

   ```
   P(Path) = Product(p_i) for all edges i in the path
   ```

   This assumes conditional independence between sequential exploit events.
   See `docs/mathematical_framework.md` for the derivation and a discussion of
   this simplifying assumption's real-world limitations.

3. **Most Probable Attack Path via Dijkstra.** Edge weights are defined as
   `w_i = -ln(p_i)`. Because `-ln(Product p_i) = Sum(-ln p_i)` and `-ln` is
   monotonically decreasing, minimizing the summed weight over a path is
   equivalent to maximizing the path's probability product. Dijkstra's
   algorithm therefore returns the most probable attack path directly.

4. **Remediation Ranking.** Each candidate edge is temporarily removed, the
   shortest (most probable) paths to the Crown Jewel asset are recomputed from
   every entry point, and edges are ranked by the number of critical attack
   paths eliminated. Complexity is `O(E x (E + V log V))`, which remains
   tractable for the small-to-medium graphs in this project's scope.

Full derivations are documented in `docs/mathematical_framework.md`.

## Repository Structure

```
attack-path-analyzer/
├── .gitignore
├── README.md
├── core-engine/
│   ├── main.py              # FastAPI application, CORS, API endpoints
│   ├── database.py          # Neo4j data layer with deterministic mock fallback
│   ├── algorithms.py        # Risk mathematics and graph algorithms
│   ├── models.py            # Pydantic v2 request/response schemas
│   ├── requirements.txt     # Pinned Python dependencies
│   └── test_algorithms.py   # unittest test suite
├── analytics-dashboard/
│   ├── package.json         # Pinned Node dependencies and scripts
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── index.css
│       ├── types.ts
│       └── components/
│           ├── GraphCanvas.tsx
│           ├── RiskMetrics.tsx
│           └── RemediationPanel.tsx
├── database-schema/
│   ├── schema.cypher
│   └── seed.cypher
└── docs/
    ├── system_architecture.md
    └── mathematical_framework.md
```

## Prerequisites

- Python 3.10 or newer
- Node.js 18 or newer (includes npm)
- Neo4j Desktop / Server 5.x (optional; the engine falls back to an internal
  mock dataset when no database is reachable)

## Backend Installation and Setup

From the repository root:

```bash
cd core-engine

# Create and activate an isolated virtual environment
python -m venv venv

# Windows (cmd.exe)
venv\Scripts\activate.bat

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# macOS / Linux
source venv/bin/activate

# Install pinned dependencies
pip install -r requirements.txt
```

### Optional: Connect to Neo4j

Set the following environment variables before starting the server. If they
are absent or the connection fails, the engine automatically serves a fully
deterministic mock dataset (`random.seed(42)`) whose schema exactly mirrors the
Cypher schema, so all demonstrations work without a database.

```bash
set NEO4J_URI=bolt://localhost:7687      # Windows cmd
set NEO4J_USER=neo4j
set NEO4J_PASSWORD=your-password-here
```

To populate a running Neo4j instance:

```bash
cypher-shell -u neo4j -p your-password-here -f ../database-schema/schema.cypher
cypher-shell -u neo4j -p your-password-here -f ../database-schema/seed.cypher
```

### Running the API Server

```bash
uvicorn main:app --reload --port 8000
```

Verification points:

- Interactive OpenAPI docs: http://localhost:8000/docs
- Topology fetch: http://localhost:8000/api/graph

### Running the Automated Test Suite

The project uses Python's native `unittest` framework; no additional test
runner is required.

```bash
cd core-engine
python -m unittest test_algorithms -v
```

Expected output terminates with `OK` and reports four executed tests:

```
test_cvss_probability_mapping ... ok
test_path_probability_product ... ok
test_most_probable_path_via_dijkstra ... ok
test_remediation_edge_ranking ... ok

----------------------------------------------------------------------
Ran 4 tests in X.XXXs

OK
```

## Frontend Installation and Setup

In a second terminal, from the repository root:

```bash
cd analytics-dashboard
npm install
npm run dev
```

The Vite development server starts at http://localhost:5173. The backend must
be running on port 8000; the frontend calls it directly across the CORS
boundary configured in `core-engine/main.py`.

Production build (enforces full TypeScript compilation first):

```bash
npm run build
npm run preview
```

## End-to-End Verification Workflow

1. Start the backend: `uvicorn main:app --reload --port 8000`
2. Start the frontend: `npm run dev`
3. Open http://localhost:5173
4. Confirm the topology canvas renders nodes colored by asset type.
5. Select an attacker entry point and a crown jewel asset from the control
   panel dropdowns, then trigger analysis.
6. Confirm the critical path highlights in crimson on the canvas and the Risk
   Metrics panel shows the path probability as a percentage.
7. Open the Remediation panel and confirm ranked, actionable mitigation
   recommendations referencing specific CVEs and configuration fixes.

## API Reference

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/graph` | Full node-edge topology map |
| POST | `/api/analyze/shortest-path` | Most probable attack path between two assets |
| GET | `/api/analytics/metrics` | Aggregate risk statistics |
| POST | `/api/remediation/suggest` | Ranked mitigation recommendations |

Request and response schemas are defined with Pydantic v2 in
`core-engine/models.py` and mirrored as TypeScript interfaces in
`analytics-dashboard/src/types.ts`.

## Documentation

- `docs/system_architecture.md`: component architecture, data flow including
  the fallback path, and the CORS boundary between frontend and backend.
- `docs/mathematical_framework.md`: complete mathematical definitions,
  proofs, modeling assumptions, and complexity analysis.

## Academic Scope Statement

This system is an engineering demonstration constructed for academic
evaluation. The independence assumption, static CVSS-derived probabilities,
and exhaustive edge-removal remediation search are deliberate simplifications
appropriate to the presentation scope and are documented where they apply.