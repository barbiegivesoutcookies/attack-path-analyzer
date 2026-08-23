// =============================================================================
// Attack Path Analyzer - Neo4j Schema Initialization
//
// Defines uniqueness constraints and indexes for the asset graph. Run this
// file once against a fresh Neo4j 5.x database before loading seed.cypher:
//
//     cypher-shell -u neo4j -p <password> -f schema.cypher
//
// Node model:
//     (:Asset {id, label, asset_type, zone, is_entry_point, is_crown_jewel})
//
// Relationship model:
//     [:EXPLOITS {cve_id, attack_vector, attack_complexity,
//                 privileges_required, user_interaction, probability}]
//
// The ``probability`` property stores the exploit likelihood derived from the
// CVSS v3.1 Exploitability subscore normalized by 3.887 and clamped to
// [0.01, 1.0]; see docs/mathematical_framework.md for the full derivation.
// =============================================================================

// -----------------------------------------------------------------------------
// Constraints
// -----------------------------------------------------------------------------

// Every asset must be uniquely addressable by its ID; this is the join key
// used by the Python driver when reconstructing the topology.
CREATE CONSTRAINT asset_id_unique IF NOT EXISTS
FOR (a:Asset) REQUIRE a.id IS UNIQUE;

// Asset IDs are always present; enforce existence for data hygiene.
CREATE CONSTRAINT asset_id_exists IF NOT EXISTS
FOR (a:Asset) REQUIRE a.id IS NOT NULL;

// -----------------------------------------------------------------------------
// Indexes
// -----------------------------------------------------------------------------

// Entry-point and crown-jewel flags drive endpoint enumeration in the API
// layer; an index keeps those lookups constant-time as the graph grows.
CREATE INDEX asset_entry_point_idx IF NOT EXISTS
FOR (a:Asset) ON (a.is_entry_point);

CREATE INDEX asset_crown_jewel_idx IF NOT EXISTS
FOR (a:Asset) ON (a.is_crown_jewel);

// CVE lookups support audit queries ("which edges reference CVE-X?").
CREATE INDEX exploits_cve_idx IF NOT EXISTS
FOR ()-[r:EXPLOITS]-() ON (r.cve_id);