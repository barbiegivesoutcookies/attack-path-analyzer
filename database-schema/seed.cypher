// =============================================================================
// Attack Path Analyzer - Deterministic Seed Dataset
//
// Loads the demonstration topology into a Neo4j 5.x database. Run AFTER
// schema.cypher:
//
//     cypher-shell -u neo4j -p <password> -f seed.cypher
//
// This dataset is structurally identical to the mock fallback generator in
// core-engine/database.py: the same node IDs, labels, asset types, zones,
// flags, CVE identifiers, and CVSS v3.1 metric combinations. The two sources
// are therefore fully interchangeable for demonstrations and testing.
//
// Probability derivation (see docs/mathematical_framework.md):
//     p_i = clamp((8.22 x AV x AC x PR x UI) / 3.887, 0.01, 1.0)
//
// Computed values used below:
//     NETWORK/LOW/NONE/NONE        -> 1.0000  (upper clamp)
//     NETWORK/LOW/LOW/NONE         -> 0.7295
//     NETWORK/HIGH/HIGH/NONE       -> 0.1815
//     ADJACENT_NETWORK/HIGH/NONE/
//         REQUIRED                 -> 0.3040
// =============================================================================

// -----------------------------------------------------------------------------
// Nodes
// -----------------------------------------------------------------------------

MERGE (a:Asset {id: 'attacker-ext'})
  SET a.label = 'External Attacker',
      a.asset_type = 'Attacker',
      a.zone = 'external',
      a.is_entry_point = true,
      a.is_crown_jewel = false;

MERGE (a:Asset {id: 'web-server-01'})
  SET a.label = 'Public Web Server',
      a.asset_type = 'Host',
      a.zone = 'dmz',
      a.is_entry_point = true,
      a.is_crown_jewel = false;

MERGE (a:Asset {id: 'vpn-gateway'})
  SET a.label = 'VPN Gateway',
      a.asset_type = 'Host',
      a.zone = 'dmz',
      a.is_entry_point = true,
      a.is_crown_jewel = false;

MERGE (a:Asset {id: 'subnet-corp'})
  SET a.label = 'Corporate Subnet 10.0.20.0/24',
      a.asset_type = 'Subnet',
      a.zone = 'internal',
      a.is_entry_point = false,
      a.is_crown_jewel = false;

MERGE (a:Asset {id: 'workstation-finance'})
  SET a.label = 'Finance Workstation',
      a.asset_type = 'Host',
      a.zone = 'internal',
      a.is_entry_point = false,
      a.is_crown_jewel = false;

MERGE (a:Asset {id: 'db-financial'})
  SET a.label = 'Financial Database',
      a.asset_type = 'Database',
      a.zone = 'core',
      a.is_entry_point = false,
      a.is_crown_jewel = true;

MERGE (a:Asset {id: 'dc-corp-01'})
  SET a.label = 'Corporate Domain Controller',
      a.asset_type = 'ActiveDirectoryDomain',
      a.zone = 'core',
      a.is_entry_point = false,
      a.is_crown_jewel = true;

// -----------------------------------------------------------------------------
// Relationships (:EXPLOITS)
// -----------------------------------------------------------------------------

// Internet-facing RCE-class vulnerability on the public web server.
MATCH (s:Asset {id: 'attacker-ext'}), (t:Asset {id: 'web-server-01'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2023-44487',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'LOW',
      r.privileges_required = 'NONE',
      r.user_interaction = 'NONE',
      r.probability = 1.0;

// VPN appliance flaw requiring user interaction; low-probability foothold.
MATCH (s:Asset {id: 'attacker-ext'}), (t:Asset {id: 'vpn-gateway'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2024-21762',
      r.attack_vector = 'ADJACENT_NETWORK',
      r.attack_complexity = 'HIGH',
      r.privileges_required = 'NONE',
      r.user_interaction = 'REQUIRED',
      r.probability = 0.304;

// PrintNightmare-class pivot from the DMZ web server into the corporate LAN.
MATCH (s:Asset {id: 'web-server-01'}), (t:Asset {id: 'subnet-corp'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2021-34527',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'LOW',
      r.privileges_required = 'LOW',
      r.user_interaction = 'NONE',
      r.probability = 0.7295;

// Overbroad firewall rule allowing the VPN gateway to reach the LAN segment.
MATCH (s:Asset {id: 'vpn-gateway'}), (t:Asset {id: 'subnet-corp'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'MISCONFIGURATION-OVERBROAD-FW-RULE',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'LOW',
      r.privileges_required = 'NONE',
      r.user_interaction = 'NONE',
      r.probability = 1.0;

// EternalBlue-class SMB exploitation of an unpatched workstation.
MATCH (s:Asset {id: 'subnet-corp'}), (t:Asset {id: 'workstation-finance'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2017-0144',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'LOW',
      r.privileges_required = 'NONE',
      r.user_interaction = 'NONE',
      r.probability = 1.0;

// ZeroLogon-style privilege escalation toward the financial database.
MATCH (s:Asset {id: 'workstation-finance'}), (t:Asset {id: 'db-financial'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2020-1472',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'LOW',
      r.privileges_required = 'LOW',
      r.user_interaction = 'NONE',
      r.probability = 0.7295;

// BlueKeep-class RDP path directly from the LAN segment to the database tier.
MATCH (s:Asset {id: 'subnet-corp'}), (t:Asset {id: 'db-financial'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2019-0708',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'HIGH',
      r.privileges_required = 'HIGH',
      r.user_interaction = 'NONE',
      r.probability = 0.1815;

// Kerberos ticket-forgery path against the domain controller.
MATCH (s:Asset {id: 'subnet-corp'}), (t:Asset {id: 'dc-corp-01'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2021-42287',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'LOW',
      r.privileges_required = 'LOW',
      r.user_interaction = 'NONE',
      r.probability = 0.7295;

// AD Certificate Services escalation from the finance workstation.
MATCH (s:Asset {id: 'workstation-finance'}), (t:Asset {id: 'dc-corp-01'})
MERGE (s)-[r:EXPLOITS]->(t)
  SET r.cve_id = 'CVE-2022-26923',
      r.attack_vector = 'NETWORK',
      r.attack_complexity = 'HIGH',
      r.privileges_required = 'HIGH',
      r.user_interaction = 'NONE',
      r.probability = 0.1815;