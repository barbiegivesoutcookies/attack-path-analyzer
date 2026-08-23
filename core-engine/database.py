"""
Data access layer for the Attack Path Analyzer.

This module owns the single responsibility of producing graph topology data
in the application's canonical schema:

    nodes: {id, label, asset_type, zone, is_entry_point, is_crown_jewel}
    edges: {source, target, cve_id, attack_vector, attack_complexity,
            privileges_required, user_interaction, probability}

Two interchangeable sources are supported:

1. **Neo4j** (primary): queried through the official ``neo4j`` Python driver
   when connection environment variables are configured and reachable.
2. **Mock fallback**: a hardcoded, fully deterministic dataset whose node
   labels, relationship properties, and CVSS fields exactly mirror the Cypher
   schema in ``database-schema/schema.cypher`` and ``seed.cypher``. The
   fallback activates automatically when Neo4j is unreachable so every
   demonstration and test runs without external infrastructure.
"""

from __future__ import annotations

import os
import random
from typing import Any, Dict, List

import networkx as nx

from algorithms import cvss_to_probability

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------

NEO4J_URI_ENV: str = "NEO4J_URI"
NEO4J_USER_ENV: str = "NEO4J_USER"
NEO4J_PASSWORD_ENV: str = "NEO4J_PASSWORD"

DEFAULT_NEO4J_URI: str = "bolt://localhost:7687"


def _neo4j_configured() -> bool:
    """Return True when Neo4j credentials are present in the environment."""
    return os.environ.get(NEO4J_PASSWORD_ENV) is not None


# ---------------------------------------------------------------------------
# Mock fallback dataset
# ---------------------------------------------------------------------------

# Node records mirror (:Asset {id, label, asset_type, zone, is_entry_point,
# is_crown_jewel}) from database-schema/seed.cypher. The topology models a
# small enterprise demilitarized zone: an external attacker pivots through a
# public web server into an internal subnet, then toward either a financial
# database or the Active Directory domain controller (the crown jewels).
_MOCK_NODES: List[Dict[str, Any]] = [
    {
        "id": "attacker-ext",
        "label": "External Attacker",
        "asset_type": "Attacker",
        "zone": "external",
        "is_entry_point": True,
        "is_crown_jewel": False,
    },
    {
        "id": "web-server-01",
        "label": "Public Web Server",
        "asset_type": "Host",
        "zone": "dmz",
        "is_entry_point": True,
        "is_crown_jewel": False,
    },
    {
        "id": "vpn-gateway",
        "label": "VPN Gateway",
        "asset_type": "Host",
        "zone": "dmz",
        "is_entry_point": True,
        "is_crown_jewel": False,
    },
    {
        "id": "subnet-corp",
        "label": "Corporate Subnet 10.0.20.0/24",
        "asset_type": "Subnet",
        "zone": "internal",
        "is_entry_point": False,
        "is_crown_jewel": False,
    },
    {
        "id": "workstation-finance",
        "label": "Finance Workstation",
        "asset_type": "Host",
        "zone": "internal",
        "is_entry_point": False,
        "is_crown_jewel": False,
    },
    {
        "id": "db-financial",
        "label": "Financial Database",
        "asset_type": "Database",
        "zone": "core",
        "is_entry_point": False,
        "is_crown_jewel": True,
    },
    {
        "id": "dc-corp-01",
        "label": "Corporate Domain Controller",
        "asset_type": "ActiveDirectoryDomain",
        "zone": "core",
        "is_entry_point": False,
        "is_crown_jewel": True,
    },
]

# Edge records mirror [:EXPLOITS {cve_id, attack_vector, attack_complexity,
# privileges_required, user_interaction}] from database-schema/seed.cypher.
# Probabilities are derived from these CVSS v3.1 metrics via the exact
# Exploitability formula implemented in algorithms.py, guaranteeing the mock
# dataset and the Neo4j dataset obey identical mathematics.
#
# Topology design notes for presentation value:
# - The direct attacker -> web server edge is highly exploitable (network
#   vector, low complexity, no privileges), modeling an internet-facing
#   RCE-class vulnerability.
# - A long low-probability chain (attacker -> VPN gateway -> subnet ->
#   workstation -> databases) exists so Dijkstra demonstrably prefers higher
#   cumulative probability over fewer hops in multi-path scenarios.
_MOCK_EDGE_RECORDS: List[Dict[str, str]] = [
    {
        "source": "attacker-ext",
        "target": "web-server-01",
        "cve_id": "CVE-2023-44487",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
    },
    {
        "source": "attacker-ext",
        "target": "vpn-gateway",
        "cve_id": "CVE-2024-21762",
        "attack_vector": "ADJACENT_NETWORK",
        "attack_complexity": "HIGH",
        "privileges_required": "NONE",
        "user_interaction": "REQUIRED",
    },
    {
        "source": "web-server-01",
        "target": "subnet-corp",
        "cve_id": "CVE-2021-34527",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "LOW",
        "user_interaction": "NONE",
    },
    {
        "source": "vpn-gateway",
        "target": "subnet-corp",
        "cve_id": "MISCONFIGURATION-OVERBROAD-FW-RULE",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
    },
    {
        "source": "subnet-corp",
        "target": "workstation-finance",
        "cve_id": "CVE-2017-0144",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
    },
    {
        "source": "workstation-finance",
        "target": "db-financial",
        "cve_id": "CVE-2020-1472",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "LOW",
        "user_interaction": "NONE",
    },
    {
        "source": "subnet-corp",
        "target": "db-financial",
        "cve_id": "CVE-2019-0708",
        "attack_vector": "NETWORK",
        "attack_complexity": "HIGH",
        "privileges_required": "HIGH",
        "user_interaction": "NONE",
    },
    {
        "source": "subnet-corp",
        "target": "dc-corp-01",
        "cve_id": "CVE-2021-42287",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "LOW",
        "user_interaction": "NONE",
    },
    {
        "source": "workstation-finance",
        "target": "dc-corp-01",
        "cve_id": "CVE-2022-26923",
        "attack_vector": "NETWORK",
        "attack_complexity": "HIGH",
        "privileges_required": "HIGH",
        "user_interaction": "NONE",
    },
]


def get_mock_graph_data() -> Dict[str, List[Dict[str, Any]]]:
    """Return the deterministic mock dataset mirroring the Neo4j schema.

    Every call re-seeds the global PRNG with ``random.seed(42)`` before any
    construction work, guaranteeing byte-identical, reproducible output
    across process restarts -- a hard requirement for repeatable academic
    presentations. The dataset itself is defined by fixed literal tables, so
    the seed additionally pins any future auxiliary randomization.

    :return: Dictionary with keys ``nodes`` and ``edges`` matching the
        canonical schema documented at module level.
    """
    random.seed(42)

    edges: List[Dict[str, Any]] = []
    for record in _MOCK_EDGE_RECORDS:
        edge: Dict[str, Any] = dict(record)
        # Derive probability from raw CVSS metrics with the same function the
        # tests validate, keeping mock and live datasets mathematically
        # consistent.
        edge["probability"] = cvss_to_probability(
            record["attack_vector"],
            record["attack_complexity"],
            record["privileges_required"],
            record["user_interaction"],
        )
        edges.append(edge)

    return {
        "nodes": [dict(node) for node in _MOCK_NODES],
        "edges": edges,
    }


# ---------------------------------------------------------------------------
# Neo4j primary source
# ---------------------------------------------------------------------------

_GRAPH_CYPHER: str = (
    "MATCH (a:Asset)-[r:EXPLOITS]->(b:Asset) "
    "RETURN a.id AS source_id, a.label AS source_label, "
    "       a.asset_type AS source_type, a.zone AS source_zone, "
    "       a.is_entry_point AS source_entry, a.is_crown_jewel AS source_jewel, "
    "       b.id AS target_id, b.label AS target_label, "
    "       b.asset_type AS target_type, b.zone AS target_zone, "
    "       b.is_entry_point AS target_entry, b.is_crown_jewel AS target_jewel, "
    "       r.cve_id AS cve_id, r.attack_vector AS attack_vector, "
    "       r.attack_complexity AS attack_complexity, "
    "       r.privileges_required AS privileges_required, "
    "       r.user_interaction AS user_interaction, r.probability AS probability "
    "ORDER BY source_id, target_id"
)


def _fetch_graph_from_neo4j() -> Dict[str, List[Dict[str, Any]]]:
    """Query the full topology from a running Neo4j instance.

    :return: Canonical-schema dictionary with keys ``nodes`` and ``edges``.
    :raises Exception: Propagates driver errors to the caller, which decides
        whether to fall back to the mock dataset.
    """
    from neo4j import GraphDatabase  # Imported lazily so the mock path works
    # on machines where the driver's transport dependencies are unavailable.

    uri: str = os.environ.get(NEO4J_URI_ENV, DEFAULT_NEO4J_URI)
    user: str = os.environ.get(NEO4J_USER_ENV, "neo4j")
    password: str = os.environ[NEO4J_PASSWORD_ENV]

    nodes_by_id: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        driver.verify_connectivity()
        with driver.session() as session:
            result = session.run(_GRAPH_CYPHER)
            for record in result:
                for prefix in ("source", "target"):
                    node_id: str = record[f"{prefix}_id"]
                    if node_id not in nodes_by_id:
                        nodes_by_id[node_id] = {
                            "id": node_id,
                            "label": record[f"{prefix}_label"],
                            "asset_type": record[f"{prefix}_type"],
                            "zone": record[f"{prefix}_zone"],
                            "is_entry_point": record[f"{prefix}_entry"],
                            "is_crown_jewel": record[f"{prefix}_jewel"],
                        }
                edges.append(
                    {
                        "source": record["source_id"],
                        "target": record["target_id"],
                        "cve_id": record["cve_id"],
                        "attack_vector": record["attack_vector"],
                        "attack_complexity": record["attack_complexity"],
                        "privileges_required": record["privileges_required"],
                        "user_interaction": record["user_interaction"],
                        "probability": float(record["probability"]),
                    }
                )
    finally:
        driver.close()

    return {"nodes": list(nodes_by_id.values()), "edges": edges}


def load_graph_data() -> tuple[Dict[str, List[Dict[str, Any]]], str]:
    """Load topology data from Neo4j, falling back to the mock dataset.

    This is the single entry point used by the API layer. The returned
    source tag lets endpoints report which backend served the request, which
    is surfaced in the dashboard for transparency during demonstrations.

    :return: Tuple ``(graph_data, source)`` where ``source`` is ``"neo4j"``
            or ``"mock"``.
    """
    if _neo4j_configured():
        try:
            return _fetch_graph_from_neo4j(), "neo4j"
        except Exception:
            # Any driver-level failure (connection refused, auth failure,
            # missing constraints) degrades gracefully to the deterministic
            # mock dataset rather than failing the demonstration.
            return get_mock_graph_data(), "mock"
    return get_mock_graph_data(), "mock"


# ---------------------------------------------------------------------------
# Conversion to NetworkX
# ---------------------------------------------------------------------------

ENTRY_POINT_TYPES: frozenset[str] = frozenset({"Attacker"})


def build_networkx_graph(graph_data: Dict[str, List[Dict[str, Any]]]) -> nx.DiGraph:
    """Convert canonical graph data into a NetworkX directed graph.

    Nodes are keyed by asset ID and carry their full attribute dictionaries;
    edges carry CVSS fields plus the precomputed exploit probability, which
    the algorithm layer consumes directly.

    :param graph_data: Canonical-schema dictionary from :func:`load_graph_data`.
    :return: Directed attack graph.
    """
    graph: nx.DiGraph = nx.DiGraph()
    for node in graph_data["nodes"]:
        graph.add_node(node["id"], **node)
    for edge in graph_data["edges"]:
        attrs: Dict[str, Any] = {
            key: value
            for key, value in edge.items()
            if key not in ("source", "target")
        }
        graph.add_edge(edge["source"], edge["target"], **attrs)
    return graph


def get_entry_points(graph: nx.DiGraph) -> List[str]:
    """Return IDs of all attacker-reachable entry-point assets.

    An asset qualifies when its ``is_entry_point`` flag is set or its type is
    the synthetic Attacker node.

    :param graph: Directed attack graph.
    :return: Sorted list of entry-point asset IDs (sorted for determinism).
    """
    return sorted(
        node_id
        for node_id, attrs in graph.nodes(data=True)
        if attrs.get("is_entry_point") or attrs.get("asset_type") in ENTRY_POINT_TYPES
    )


def get_crown_jewels(graph: nx.DiGraph) -> List[str]:
    """Return IDs of all crown-jewel assets.

    :param graph: Directed attack graph.
    :return: Sorted list of crown-jewel asset IDs (sorted for determinism).
    """
    return sorted(
        node_id
        for node_id, attrs in graph.nodes(data=True)
        if attrs.get("is_crown_jewel")
    )