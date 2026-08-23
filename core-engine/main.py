"""
FastAPI application for the Attack Path Analyzer.

Exposes the analysis engine over HTTP with strict Pydantic v2 validation:

    GET  /api/graph                    Full node-edge topology map.
    POST /api/analyze/shortest-path    Most probable attack path computation.
    GET  /api/analytics/metrics        Aggregate risk statistics.
    POST /api/remediation/suggest      Ranked mitigation recommendations.

CORS is explicitly configured to allow the Vite development server origin
(http://localhost:5173) so the React dashboard can call this API directly
from the browser during local development and academic presentation without
the browser's same-origin policy blocking the requests.
"""

from __future__ import annotations

from typing import Any, Dict, List

import networkx as nx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import algorithms
import database
from models import (
    GraphResponse,
    MetricsResponse,
    PathEdgeDetail,
    RemediationCandidate,
    RemediationRequest,
    RemediationResponse,
    ShortestPathRequest,
    ShortestPathResponse,
    TopVulnerableAsset,
)

# ---------------------------------------------------------------------------
# Application and CORS configuration
# ---------------------------------------------------------------------------

#: Origins permitted to call this API from a browser. The Vite dev server
#: binds to http://localhost:5173 by default; without an explicit CORS grant
#: the browser blocks every cross-origin fetch the dashboard attempts.
ALLOWED_ORIGINS: List[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app: FastAPI = FastAPI(
    title="Attack Path Analyzer API",
    description=(
        "Graph-theoretic cyber attack path analysis and risk prediction "
        "engine. Computes most-probable attack paths from CVSS-derived "
        "exploit probabilities and ranks remediation actions by the number "
        "of critical paths they eliminate."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_attack_graph() -> tuple[nx.DiGraph, str]:
    """Load topology data and convert it into a NetworkX directed graph.

    :return: Tuple ``(graph, source)`` where ``source`` names the data
        backend that served the request (``"neo4j"`` or ``"mock"``).
    """
    graph_data, source = database.load_graph_data()
    return database.build_networkx_graph(graph_data), source


def _resolve_analysis_endpoints(
    graph: nx.DiGraph, source_id: str, target_id: str
) -> List[str]:
    """Resolve the entry-point set used for path enumeration.

    When the caller supplies the synthetic Attacker node as source, every
    flagged entry point becomes an origin; otherwise only the requested
    source is used. This mirrors how a real attacker can choose among any
    externally reachable foothold.

    :param graph: Directed attack graph.
    :param source_id: Requested source asset ID.
    :param target_id: Requested target asset ID.
    :return: List of entry-point asset IDs to enumerate from.
    """
    if graph.nodes[source_id].get("asset_type") == "Attacker":
        entry_points: List[str] = database.get_entry_points(graph)
        if source_id not in entry_points:
            entry_points.append(source_id)
        return entry_points
    return [source_id]


def _validate_endpoint_nodes(graph: nx.DiGraph, source_id: str, target_id: str) -> None:
    """Raise HTTP 404 when either endpoint asset does not exist in the graph.

    :param graph: Directed attack graph.
    :param source_id: Requested source asset ID.
    :param target_id: Requested target asset ID.
    """
    missing: List[str] = [
        node_id for node_id in (source_id, target_id) if node_id not in graph
    ]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown asset ID(s): {', '.join(missing)}",
        )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/api/graph", response_model=GraphResponse, tags=["topology"])
def get_graph() -> GraphResponse:
    """Fetch the entire node-edge topology map.

    Served from Neo4j when configured and reachable; otherwise from the
    deterministic mock dataset. The response ``source`` field in the raw
    payload is intentionally omitted here so the schema stays identical
    across backends; clients detect fallback via /api/analytics/metrics.
    """
    graph_data, _source = database.load_graph_data()
    return GraphResponse(**graph_data)


@app.post("/api/analyze/shortest-path", response_model=ShortestPathResponse, tags=["analysis"])
def analyze_shortest_path(request: ShortestPathRequest) -> ShortestPathResponse:
    """Compute the most probable attack path between two assets.

    The engine derives per-edge exploit probabilities from CVSS v3.1
    Exploitability metrics, transforms them into additive difficulty weights
    w_i = -ln(p_i), and runs Dijkstra's algorithm -- which, by the monotone
    equivalence -ln(Product p_i) = Sum(-ln p_i), returns the path maximizing
    the true probability product rather than merely minimizing hops.
    """
    graph, _source = _load_attack_graph()
    _validate_endpoint_nodes(graph, request.source_id, request.target_id)

    try:
        path_nodes, probability = algorithms.most_probable_attack_path(
            graph, request.source_id, request.target_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    path_edges: List[PathEdgeDetail] = []
    for u, v in zip(path_nodes, path_nodes[1:]):
        edge_attrs: Dict[str, Any] = graph.edges[u, v]
        path_edges.append(
            PathEdgeDetail(
                source=u,
                target=v,
                cve_id=str(edge_attrs.get("cve_id", "MISCONFIGURATION")),
                probability=algorithms.edge_probability(edge_attrs),
            )
        )

    return ShortestPathResponse(
        path_nodes=path_nodes,
        path_edges=path_edges,
        path_probability=probability,
        path_length_hops=len(path_nodes) - 1,
    )


@app.get("/api/analytics/metrics", response_model=MetricsResponse, tags=["analysis"])
def get_metrics() -> MetricsResponse:
    """Return high-level aggregate risk metrics for the dashboard.

    Metrics include total enumerated attack paths, average path length in
    hops, and the top vulnerable assets ranked by incoming exploitability
    exposure.
    """
    graph, _source = _load_attack_graph()
    entry_points: List[str] = database.get_entry_points(graph)
    crown_jewels: List[str] = database.get_crown_jewels(graph)

    # Aggregate metrics across all crown jewels so the dashboard reflects
    # total organizational exposure rather than a single target's.
    total_paths: int = 0
    total_length_sum: int = 0
    for jewel in crown_jewels:
        metrics: Dict[str, Any] = algorithms.compute_graph_metrics(
            graph, entry_points, jewel
        )
        total_paths += int(metrics["total_attack_paths"])
        path_count = int(metrics["total_attack_paths"])
        total_length_sum += int(round(float(metrics["average_path_length"]) * path_count))

    average_length: float = (
        total_length_sum / total_paths if total_paths > 0 else 0.0
    )

    # Exposure ranking uses all edges regardless of target since incoming
    # exploitability mass is target-independent.
    exposure: Dict[str, float] = {}
    for _u, v, data in graph.edges(data=True):
        exposure[v] = exposure.get(v, 0.0) + algorithms.edge_probability(data)
    top_assets: List[TopVulnerableAsset] = [
        TopVulnerableAsset(asset_id=node, incoming_exposure=round(score, 6))
        for node, score in sorted(
            exposure.items(), key=lambda kv: kv[1], reverse=True
        )[:5]
    ]

    return MetricsResponse(
        total_attack_paths=total_paths,
        average_path_length=round(average_length, 3),
        top_vulnerable_assets=top_assets,
    )


@app.post("/api/remediation/suggest", response_model=RemediationResponse, tags=["remediation"])
def suggest_remediation(request: RemediationRequest) -> RemediationResponse:
    """Compute and return the optimal mitigation strategy.

    Each candidate edge is temporarily removed, shortest paths to the crown
    jewel are recomputed from all entry points, and edges are ranked by the
    number of critical attack paths eliminated. Overall complexity is
    O(E x (E + V log V)), documented fully in algorithms.py.
    """
    graph, _source = _load_attack_graph()
    _validate_endpoint_nodes(graph, request.source_id, request.target_id)

    entry_points: List[str] = _resolve_analysis_endpoints(
        graph, request.source_id, request.target_id
    )

    baseline_paths: List[List[str]] = algorithms.all_attack_paths(
        graph, entry_points, request.target_id
    )
    baseline_count: int = len(baseline_paths)
    if baseline_count == 0:
        raise HTTPException(
            status_code=422,
            detail=(
                f"No attack path exists from {request.source_id!r} to "
                f"{request.target_id!r}; no remediation is required."
            ),
        )

    rankings: List[Dict[str, Any]] = algorithms.rank_remediation_edges(
        graph, entry_points, request.target_id
    )

    candidates: List[RemediationCandidate] = [
        RemediationCandidate(
            edge=item["edge"],  # type: ignore[arg-type]
            paths_eliminated=int(item["paths_eliminated"]),  # type: ignore[arg-type]
            remaining_paths=int(item["remaining_paths"]),  # type: ignore[arg-type]
            recommendation=str(item["recommendation"]),
        )
        for item in rankings
        if int(item["paths_eliminated"]) > 0  # type: ignore[arg-type]
    ]

    return RemediationResponse(
        baseline_path_count=baseline_count,
        candidates=candidates,
    )


@app.get("/api/health", tags=["system"])
def health_check() -> Dict[str, str]:
    """Liveness probe reporting which data backend is currently active."""
    _graph, source = _load_attack_graph()
    return {"status": "ok", "data_source": source}


# Allow running directly via `python main.py` for quick demonstrations.
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)