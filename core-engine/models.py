"""
Pydantic v2 request/response schemas for the Attack Path Analyzer API.

These models enforce strict validation at the transport boundary: malformed
requests are rejected with HTTP 422 before any business logic executes, and
every response is serialized through a declared schema so the frontend can
rely on a stable contract. The TypeScript interfaces in
``analytics-dashboard/src/types.ts`` mirror these definitions.
"""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, ConfigDict, Field


class AssetNode(BaseModel):
    """A single asset node in the attack graph.

    Node labels follow the Neo4j schema defined in
    ``database-schema/schema.cypher``: Host, Subnet, Database, and
    ActiveDirectoryDomain assets, plus the synthetic Attacker entry node.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, description="Unique asset identifier.")
    label: str = Field(
        ..., min_length=1, description="Human-readable asset name."
    )
    asset_type: str = Field(
        ...,
        description=(
            "One of: Attacker, Host, Subnet, Database, ActiveDirectoryDomain."
        ),
    )
    zone: str = Field(
        default="internal",
        description="Network zone the asset resides in (e.g., dmz, internal, core).",
    )
    is_entry_point: bool = Field(
        default=False,
        description="True if an external attacker can reach this asset directly.",
    )
    is_crown_jewel: bool = Field(
        default=False,
        description="True if compromise of this asset constitutes mission impact.",
    )


class VulnerabilityEdge(BaseModel):
    """A directed exploitability edge between two assets.

    Edge properties exactly mirror the ``EXPLOITS`` relationship schema in
    ``database-schema/schema.cypher`` and the mock dataset generator in
    ``database.py``, making both data sources structurally interchangeable.
    """

    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., min_length=1, description="Source asset ID.")
    target: str = Field(..., min_length=1, description="Target asset ID.")
    cve_id: str = Field(
        default="MISCONFIGURATION",
        description="CVE identifier, or MISCONFIGURATION for non-CVE edges.",
    )
    attack_vector: str = Field(
        default="NETWORK",
        description="CVSS v3.1 Attack Vector: NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL.",
    )
    attack_complexity: str = Field(
        default="LOW",
        description="CVSS v3.1 Attack Complexity: LOW or HIGH.",
    )
    privileges_required: str = Field(
        default="NONE",
        description="CVSS v3.1 Privileges Required: NONE, LOW, or HIGH.",
    )
    user_interaction: str = Field(
        default="NONE",
        description="CVSS v3.1 User Interaction: NONE or REQUIRED.",
    )
    probability: float = Field(
        ...,
        ge=0.01,
        le=1.0,
        description=(
            "Precomputed exploit probability derived from the CVSS "
            "Exploitability subscore, clamped to [0.01, 1.0]."
        ),
    )


class GraphResponse(BaseModel):
    """Response payload of GET /api/graph."""

    nodes: List[AssetNode]
    edges: List[VulnerabilityEdge]


class ShortestPathRequest(BaseModel):
    """Request payload of POST /api/analyze/shortest-path."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(
        ..., min_length=1, description="Attacker entry-point asset ID."
    )
    target_id: str = Field(
        ..., min_length=1, description="Crown-jewel target asset ID."
    )


class PathEdgeDetail(BaseModel):
    """One edge along a computed critical path with its risk attributes."""

    source: str
    target: str
    cve_id: str
    probability: float = Field(..., ge=0.01, le=1.0)


class ShortestPathResponse(BaseModel):
    """Response payload of POST /api/analyze/shortest-path.

    ``path_probability`` is P(Path) = Product(p_i) under the conditional
    independence assumption documented in algorithms.py.
    """

    path_nodes: List[str] = Field(..., min_length=1)
    path_edges: List[PathEdgeDetail]
    path_probability: float = Field(..., ge=0.0, le=1.0)
    path_length_hops: int = Field(..., ge=0)


class TopVulnerableAsset(BaseModel):
    """An asset ranked by incoming exploitability exposure."""

    asset_id: str
    incoming_exposure: float = Field(..., ge=0.0)


class MetricsResponse(BaseModel):
    """Response payload of GET /api/analytics/metrics."""

    total_attack_paths: int = Field(..., ge=0)
    average_path_length: float = Field(..., ge=0.0)
    top_vulnerable_assets: List[TopVulnerableAsset]


class RemediationRequest(BaseModel):
    """Request payload of POST /api/remediation/suggest."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(
        ..., min_length=1, description="Attacker entry-point asset ID."
    )
    target_id: str = Field(
        ..., min_length=1, description="Crown-jewel target asset ID."
    )


class RemediationCandidate(BaseModel):
    """One ranked mitigation candidate produced by edge-removal analysis."""

    edge: Dict[str, str] = Field(
        ..., description='Object with "source" and "target" asset IDs.'
    )
    paths_eliminated: int = Field(..., ge=0)
    remaining_paths: int = Field(..., ge=0)
    recommendation: str = Field(..., min_length=1)


class RemediationResponse(BaseModel):
    """Response payload of POST /api/remediation/suggest."""

    baseline_path_count: int = Field(..., ge=0)
    candidates: List[RemediationCandidate]


class ErrorResponse(BaseModel):
    """Uniform error envelope returned with 4xx responses."""

    detail: str