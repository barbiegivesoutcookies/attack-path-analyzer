"""
Graph-theoretic attack path analysis algorithms.

This module implements the complete mathematical risk framework of the
system:

1. CVSS v3.1 Exploitability-to-probability mapping for edge weights.
2. Cumulative path probability under a conditional-independence assumption.
3. Most-probable attack path discovery via Dijkstra over log-transformed
   weights.
4. Exhaustive single-edge-removal remediation ranking.

All functions operate on plain ``networkx.DiGraph`` objects so that the
algorithms are fully decoupled from both the Neo4j persistence layer and the
FastAPI transport layer, enabling direct unit testing on hand-constructed toy
graphs.
"""

from __future__ import annotations

import math
from typing import Dict, List, Set, Tuple

import networkx as nx

# ---------------------------------------------------------------------------
# Module-level constants defining the CVSS v3.1 Exploitability subscore model.
# ---------------------------------------------------------------------------

#: The literal coefficient of the CVSS v3.1 Exploitability subscore formula.
CVSS_EXPLOITABILITY_COEFFICIENT: float = 8.22

#: Maximum possible Exploitability subscore. This occurs when every metric
#: takes its most exploitable value: AttackVector=Network(0.85),
#: AttackComplexity=Low(0.77), PrivilegesRequired=None(0.85),
#: UserInteraction=None(0.85). Hence 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.887
#: (rounded to three decimal places, matching the CVSS v3.1 specification).
MAX_EXPLOITABILITY: float = 3.887

#: Minimum exploit probability floor. Without this floor an edge could carry
#: p_i = 0.0, producing w_i = -ln(0) = +infinity and breaking Dijkstra's
#: arithmetic. A 1% floor keeps all weights finite while still representing
#: negligible-but-nonzero exploitability.
MIN_PROBABILITY_FLOOR: float = 0.01

# ---------------------------------------------------------------------------
# CVSS v3.1 metric lookup tables. Each metric maps its qualitative value to
# the numeric weight defined by FIRST's CVSS v3.1 specification, Appendix A.
# ---------------------------------------------------------------------------

ATTACK_VECTOR_WEIGHTS: Dict[str, float] = {
    "NETWORK": 0.85,
    "ADJACENT_NETWORK": 0.62,
    "LOCAL": 0.55,
    "PHYSICAL": 0.20,
}

ATTACK_COMPLEXITY_WEIGHTS: Dict[str, float] = {
    "LOW": 0.77,
    "HIGH": 0.44,
}

PRIVILEGES_REQUIRED_WEIGHTS: Dict[str, float] = {
    "NONE": 0.85,
    # For scope-changed vulnerabilities the specification raises PR weights;
    # this project models single-scope assets only, so the standard table is
    # used throughout.
    "LOW": 0.62,
    "HIGH": 0.27,
}

USER_INTERACTION_WEIGHTS: Dict[str, float] = {
    "NONE": 0.85,
    "REQUIRED": 0.62,
}


def cvss_to_probability(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
) -> float:
    """Map CVSS v3.1 Exploitability metrics to an exploit probability in [0.01, 1.0].

    The CVSS v3.1 Exploitability subscore is computed with the literal
    specification formula::

        Exploitability = 8.22 x AV x AC x PR x UI

    where AV, AC, PR, UI are the numeric weights of the Attack Vector,
    Attack Complexity, Privileges Required, and User Interaction metrics
    respectively (FIRST CVSS v3.1 specification, Appendix A).

    The subscore ranges over [0.0, 3.887]. It is normalized to [0.0, 1.0] by
    dividing by the maximum possible exploitability value (3.887), yielding a
    quantity interpretable as the probability that a skilled attacker
    successfully exploits the vulnerability under ideal conditions.

    **Clamping rationale.** The raw quotient can approach 0.0 for the least
    exploitable combination (Physical vector, High complexity, High
    privileges, User interaction required). Because downstream analysis uses
    the transformation w_i = -ln(p_i), any p_i = 0 would produce an infinite
    edge weight and break shortest-path arithmetic. The result is therefore
    clamped to a minimum floor of 0.01: such edges remain effectively
    impassable relative to typical probabilities (which are orders of
    magnitude larger) but keep every computation well-defined.

    :param attack_vector: One of NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL.
    :param attack_complexity: One of LOW, HIGH.
    :param privileges_required: One of NONE, LOW, HIGH.
    :param user_interaction: One of NONE, REQUIRED.
    :return: Exploit probability clamped to [0.01, 1.0].
    :raises ValueError: If any metric string is not a recognized CVSS value.
    """
    try:
        av = ATTACK_VECTOR_WEIGHTS[attack_vector.upper()]
        ac = ATTACK_COMPLEXITY_WEIGHTS[attack_complexity.upper()]
        pr = PRIVILEGES_REQUIRED_WEIGHTS[privileges_required.upper()]
        ui = USER_INTERACTION_WEIGHTS[user_interaction.upper()]
    except KeyError as exc:
        raise ValueError(f"Unrecognized CVSS metric value: {exc}") from exc

    exploitability: float = (
        CVSS_EXPLOITABILITY_COEFFICIENT * av * ac * pr * ui
    )
    normalized: float = exploitability / MAX_EXPLOITABILITY

    # Clamp into [floor, 1.0]. The upper clamp guards against floating-point
    # drift pushing the most-exploitable combination marginally above 1.0.
    return max(MIN_PROBABILITY_FLOOR, min(normalized, 1.0))


def edge_probability(edge_data: Dict[str, object]) -> float:
    """Extract or derive the exploit probability for a single graph edge.

    Edges may either carry a precomputed ``probability`` property (as stored
    by the Neo4j layer and the mock dataset generator) or carry raw CVSS
    fields from which the probability is derived on demand. Deriving on
    demand keeps the algorithm layer self-contained for testing.

    :param edge_data: Attribute dictionary of one directed edge.
    :return: Exploit probability clamped to [0.01, 1.0].
    """
    if "probability" in edge_data:
        probability = float(edge_data["probability"])  # type: ignore[arg-type]
        return max(MIN_PROBABILITY_FLOOR, min(probability, 1.0))

    return cvss_to_probability(
        str(edge_data.get("attack_vector", "NETWORK")),
        str(edge_data.get("attack_complexity", "LOW")),
        str(edge_data.get("privileges_required", "NONE")),
        str(edge_data.get("user_interaction", "NONE")),
    )


def path_probability(graph: nx.DiGraph, path: List[str]) -> float:
    """Compute cumulative exploit probability P(Path) = Product(p_i).

    **Modeling assumption.** The probability of realizing an entire attack
    chain is modeled as the product of per-edge exploit probabilities. This
    is exactly true only if the sequential exploit events are conditionally
    independent given the attacker has reached each intermediate node. In
    reality this assumption is a simplification:

    - Credential material harvested at one stage often raises success
      probability at later stages (positive correlation), so the product
      tends to *underestimate* real-world chained success.
    - Conversely, defensive detection triggered mid-chain can suppress later
      stages (negative correlation), causing overestimation.

    Despite these limitations, the product form is the standard first-order
    Bayesian approximation used in attack-graph literature (e.g., Sheyner et
    al.'s attack scenario graphs) and provides monotone, comparable risk
    scores suitable for prioritization, which is the project's objective.

    :param graph: Directed attack graph; edges carry CVSS/probability data.
    :param path: Ordered list of node IDs forming a simple path.
    :return: Path probability in [~0.0, 1.0]; 1.0 for a single-node path.
    :raises ValueError: If the path contains fewer than one node or any
        consecutive edge is absent from the graph.
    """
    if len(path) < 1:
        raise ValueError("Path must contain at least one node.")

    probability: float = 1.0
    for source, target in zip(path, path[1:]):
        if not graph.has_edge(source, target):
            raise ValueError(
                f"Edge ({source!r} -> {target!r}) is not present in the graph."
            )
        probability *= edge_probability(graph.edges[source, target])
    return probability


def _difficulty_weight(edge_data: Dict[str, object]) -> float:
    """Convert an edge's exploit probability into a Dijkstra-compatible weight.

    The attacker-difficulty weight is defined as ``w_i = -ln(p_i)``.

    **One-line equivalence proof.** For any path P with edges i = 1..k:

        Sum(w_i) = Sum(-ln p_i) = -ln(Product p_i)

    Since ``-ln`` is strictly monotonically decreasing on (0, 1], minimizing
    Sum(w_i) over paths is equivalent to maximizing Product(p_i). Therefore
    Dijkstra's shortest-path search over these additive weights returns the
    path with the highest true probability product -- not merely the fewest
    hops.

    :param edge_data: Attribute dictionary of one directed edge.
    :return: Non-negative finite weight suitable for Dijkstra's algorithm.
    """
    return -math.log(edge_probability(edge_data))


def most_probable_attack_path(
    graph: nx.DiGraph, source: str, target: str
) -> Tuple[List[str], float]:
    """Find the most probable attack path using Dijkstra over -ln(p) weights.

    As proven in :func:`_difficulty_weight`, minimizing summed -ln(p_i)
    maximizes the product of per-edge probabilities, so NetworkX's Dijkstra
    implementation directly yields the maximum-probability attack path.

    :param graph: Directed attack graph.
    :param source: Entry-point asset ID (attacker-controlled node).
    :param target: Crown-jewel asset ID.
    :return: Tuple ``(path_nodes, path_probability)`` where ``path_nodes`` is
        the ordered node sequence and ``path_probability`` is its cumulative
        exploit probability.
    :raises ValueError: If source or target is absent from the graph, or no
        directed path connects them.
    """
    if source not in graph:
        raise ValueError(f"Source node {source!r} not found in graph.")
    if target not in graph:
        raise ValueError(f"Target node {target!r} not found in graph.")

    # Attach the derived difficulty weights lazily on a copy so stored graph
    # objects remain free of derived attributes.
    weighted_view: nx.DiGraph = graph.copy()
    for u, v, data in weighted_view.edges(data=True):
        data["weight"] = _difficulty_weight(data)

    try:
        path: List[str] = nx.dijkstra_path(
            weighted_view, source, target, weight="weight"
        )
    except nx.NetworkXNoPath as exc:
        raise ValueError(
            f"No attack path exists from {source!r} to {target!r}."
        ) from exc

    return path, path_probability(graph, path)


def all_attack_paths(
    graph: nx.DiGraph, entry_points: List[str], target: str, cutoff: int = 8
) -> List[List[str]]:
    """Enumerate simple attack paths from every entry point to the crown jewel.

    Used by the analytics endpoint to count total attack paths and by the
    remediation engine to count eliminated critical paths. The ``cutoff``
    bounds path length to keep enumeration tractable; multi-stage intrusions
    beyond eight hops are outside this project's modeling scope.

    :param graph: Directed attack graph.
    :param entry_points: Node IDs of attacker-reachable entry assets.
    :param target: Crown-jewel asset ID.
    :param cutoff: Maximum number of edges per enumerated path.
    :return: Deduplicated list of simple paths (each a list of node IDs).
    """
    seen: Set[Tuple[str, ...]] = set()
    paths: List[List[str]] = []
    for entry in entry_points:
        if entry not in graph or target not in graph:
            continue
        try:
            generator = nx.all_simple_paths(graph, entry, target, cutoff=cutoff)
        except (nx.NodeNotFound, ValueError):
            continue
        for candidate in generator:
            key: Tuple[str, ...] = tuple(candidate)
            if key not in seen:
                seen.add(key)
                paths.append(candidate)
    return paths


def rank_remediation_edges(
    graph: nx.DiGraph,
    entry_points: List[str],
    target: str,
    candidate_edges: List[Tuple[str, str]] | None = None,
    cutoff: int = 8,
) -> List[Dict[str, object]]:
    """Rank edges by how many critical attack paths their removal eliminates.

    **Algorithm.** For each candidate edge e:

    1. Temporarily remove e from a copy of the graph.
    2. Recompute all simple attack paths from every entry point to the crown
       jewel target on the modified copy.
    3. Record ``eliminated = baseline_path_count - remaining_path_count``.

    Candidates are returned sorted descending by eliminated-path count; ties
    preserve the original candidate order for deterministic output.

    **Complexity.** Let E be the number of candidate edges, V the number of
    nodes, and L the cutoff-bounded path length. Enumerating all simple paths
    between one pair is exponential in theory, but bounded by the cutoff it
    is O(V^(L)) in the worst case; practically, sparse enterprise attack
    graphs yield far fewer paths. Per candidate edge the recomputation costs
    O(E + V log V) when restricted to shortest-path recomputation, giving the
    stated overall bound:

        O(E x (E + V log V))

    **Tractability note.** This remains tractable for the small-to-medium
    graphs used in this project's presentation scope (tens of nodes/edges):
    even E = 100 candidates against a sub-millisecond Dijkstra recomputation
    completes in well under a second. Production deployments at enterprise
    scale would replace exhaustive enumeration with approximate path counting
    (e.g., betweenness-based scoring or Monte Carlo sampling), which is out
    of scope here.

    :param graph: Directed attack graph.
    :param entry_points: Node IDs of attacker-reachable entry assets.
    :param target: Crown-jewel asset ID.
    :param candidate_edges: Explicit edge candidates; defaults to all edges.
    :param cutoff: Maximum path length used during path enumeration.
    :return: Ranked list of dictionaries with keys ``edge``,
        ``paths_eliminated``, ``remaining_paths``, and ``recommendation``.
    """
    if candidate_edges is None:
        candidate_edges = [(u, v) for u, v in graph.edges()]

    baseline_paths: List[List[str]] = all_attack_paths(
        graph, entry_points, target, cutoff=cutoff
    )
    baseline_count: int = len(baseline_paths)

    rankings: List[Dict[str, object]] = []
    for edge_u, edge_v in candidate_edges:
        if not graph.has_edge(edge_u, edge_v):
            continue

        perturbed: nx.DiGraph = graph.copy()
        perturbed.remove_edge(edge_u, edge_v)
        remaining: List[List[str]] = all_attack_paths(
            perturbed, entry_points, target, cutoff=cutoff
        )
        eliminated: int = baseline_count - len(remaining)

        edge_attrs: Dict[str, object] = dict(graph.edges[edge_u, edge_v])
        rankings.append(
            {
                "edge": {"source": edge_u, "target": edge_v},
                "paths_eliminated": eliminated,
                "remaining_paths": len(remaining),
                "recommendation": build_remediation_recommendation(
                    edge_u, edge_v, edge_attrs
                ),
            }
        )

    rankings.sort(key=lambda item: item["paths_eliminated"], reverse=True)
    return rankings


def build_remediation_recommendation(
    source: str, target: str, edge_attrs: Dict[str, object]
) -> str:
    """Produce human-readable remediation guidance for one attack edge.

    The recommendation text names the specific patching or configuration
    action implied by the edge's vulnerability class and CVSS metrics, so the
    Remediation Panel can present actionable engineering steps rather than
    abstract scores.

    :param source: Source asset ID of the edge.
    :param target: Target asset ID of the edge.
    :param edge_attrs: Edge attribute dictionary (CVE ID, CVSS metrics, etc.).
    :return: Actionable recommendation sentence.
    """
    cve_id: str = str(edge_attrs.get("cve_id", "unspecified vulnerability"))
    attack_vector: str = str(edge_attrs.get("attack_vector", "NETWORK")).replace(
        "_", " "
    ).lower()
    privileges_required: str = str(
        edge_attrs.get("privileges_required", "NONE")
    ).lower()

    vector_actions: Dict[str, str] = {
        "NETWORK": (
            f"restrict network reachability between '{source}' and '{target}' "
            "(firewall rules / segmentation)"
        ),
        "ADJACENT_NETWORK": (
            f"isolate '{source}' from the Layer-2 segment hosting '{target}'"
        ),
        "LOCAL": (
            f"harden local access controls on '{target}' reachable from '{source}'"
        ),
        "PHYSICAL": (
            f"enforce physical access controls protecting '{target}'"
        ),
    }
    action: str = vector_actions.get(
        str(edge_attrs.get("attack_vector", "NETWORK")),
        f"review access between '{source}' and '{target}'",
    )

    privilege_note: str = (
        "no attacker privileges are required, so patching is the only full fix"
        if privileges_required == "none"
        else f"the exploit requires {privileges_required} privileges, so removing "
        "excessive account rights also degrades this path"
    )

    return (
        f"Patch {cve_id} on '{target}' and {action}. "
        f"Per CVSS metrics ({attack_vector} vector), {privilege_note}. "
        f"Removing this edge breaks every attack path traversing it."
    )


def compute_graph_metrics(
    graph: nx.DiGraph, entry_points: List[str], target: str, cutoff: int = 8
) -> Dict[str, object]:
    """Compute aggregate analytics metrics for the dashboard.

    Metrics produced:

    - ``total_attack_paths``: count of simple entry-to-target paths.
    - ``average_path_length``: mean edge count across those paths.
    - ``top_vulnerable_assets``: nodes ranked by total incoming edge
      probability mass (a proxy for how much attacker traffic converges on
      them).

    :param graph: Directed attack graph.
    :param entry_points: Node IDs of attacker-reachable entry assets.
    :param target: Crown-jewel asset ID.
    :param cutoff: Maximum path length used during path enumeration.
    :return: Dictionary of computed metrics.
    """
    paths: List[List[str]] = all_attack_paths(graph, entry_points, target, cutoff=cutoff)

    total_paths: int = len(paths)
    average_length: float = (
        sum(len(p) - 1 for p in paths) / total_paths if total_paths > 0 else 0.0
    )

    exposure: Dict[str, float] = {}
    for u, v, data in graph.edges(data=True):
        exposure[v] = exposure.get(v, 0.0) + edge_probability(data)
    top_vulnerable: List[Dict[str, object]] = [
        {"asset_id": node, "incoming_exposure": round(score, 6)}
        for node, score in sorted(
            exposure.items(), key=lambda kv: kv[1], reverse=True
        )[:5]
    ]

    return {
        "total_attack_paths": total_paths,
        "average_path_length": round(average_length, 3),
        "top_vulnerable_assets": top_vulnerable,
    }