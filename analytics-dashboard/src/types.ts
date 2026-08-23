/**
 * Shared TypeScript interfaces mirroring the Pydantic v2 response schemas
 * defined in core-engine/models.py. Keeping both sides structurally identical
 * guarantees the frontend compiles against the exact API contract.
 */

/** A single asset node in the attack graph (mirrors AssetNode). */
export interface AssetNode {
  id: string;
  label: string;
  asset_type: string;
  zone: string;
  is_entry_point: boolean;
  is_crown_jewel: boolean;
}

/** A directed exploitability edge (mirrors VulnerabilityEdge). */
export interface VulnerabilityEdge {
  source: string;
  target: string;
  cve_id: string;
  attack_vector: string;
  attack_complexity: string;
  privileges_required: string;
  user_interaction: string;
  probability: number;
}

/** Response payload of GET /api/graph (mirrors GraphResponse). */
export interface GraphResponse {
  nodes: AssetNode[];
  edges: VulnerabilityEdge[];
}

/** One edge along a computed critical path (mirrors PathEdgeDetail). */
export interface PathEdgeDetail {
  source: string;
  target: string;
  cve_id: string;
  probability: number;
}

/** Response payload of POST /api/analyze/shortest-path. */
export interface ShortestPathResponse {
  path_nodes: string[];
  path_edges: PathEdgeDetail[];
  path_probability: number;
  path_length_hops: number;
}

/** An asset ranked by incoming exploitability exposure. */
export interface TopVulnerableAsset {
  asset_id: string;
  incoming_exposure: number;
}

/** Response payload of GET /api/analytics/metrics. */
export interface MetricsResponse {
  total_attack_paths: number;
  average_path_length: number;
  top_vulnerable_assets: TopVulnerableAsset[];
}

/** One ranked mitigation candidate (mirrors RemediationCandidate). */
export interface RemediationCandidate {
  edge: { source: string; target: string };
  paths_eliminated: number;
  remaining_paths: number;
  recommendation: string;
}

/** Response payload of POST /api/remediation/suggest. */
export interface RemediationResponse {
  baseline_path_count: number;
  candidates: RemediationCandidate[];
}

/** Request payload shared by the analysis and remediation endpoints. */
export interface AnalysisRequest {
  source_id: string;
  target_id: string;
}