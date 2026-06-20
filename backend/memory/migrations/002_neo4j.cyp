// =============================================================================
// AI SOC Memory Platform — Layer 3 (Relationship Memory)
// Neo4j schema: constraints + indexes for the cyber knowledge graph.
// Idempotent: safe to re-run. Designed for the GraphRAG engine.
//
// Node labels : User, Host, Asset, IP, Domain, Process, ThreatActor, Campaign,
//               MalwareFamily, Credential, Incident, IOC, Playbook
// Relationships:
//   LOGGED_INTO      User   -> Host/Asset
//   CONNECTED_TO     IP     -> IP/Host
//   COMMUNICATED_WITH Host  -> Host/IP
//   COMPROMISED_BY   User/Host/Asset -> ThreatActor
//   BELONGS_TO       Host/Asset -> Asset (grouping)
//   TARGETS          ThreatActor/Campaign -> User/Host/Asset
//   OWNS             User -> Asset
//   RESOLVES_TO      Domain -> IP
//   EXECUTED         Host/Process -> Process
//   LINKED_TO_INCIDENT *     -> Incident (everything)
// =============================================================================

// ---- Uniqueness constraints (also create backing indexes) ----
CREATE CONSTRAINT user_id IF NOT EXISTS
FOR (n:User) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT host_id IF NOT EXISTS
FOR (n:Host) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT asset_id IF NOT EXISTS
FOR (n:Asset) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT ip_value IF NOT EXISTS
FOR (n:IP) REQUIRE n.value IS UNIQUE;

CREATE CONSTRAINT domain_value IF NOT EXISTS
FOR (n:Domain) REQUIRE n.value IS UNIQUE;

CREATE CONSTRAINT process_id IF NOT EXISTS
FOR (n:Process) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT threat_actor_id IF NOT EXISTS
FOR (n:ThreatActor) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT campaign_id IF NOT EXISTS
FOR (n:Campaign) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT malware_id IF NOT EXISTS
FOR (n:MalwareFamily) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT incident_id IF NOT EXISTS
FOR (n:Incident) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT ioc_id IF NOT EXISTS
FOR (n:IOC) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT playbook_id IF NOT EXISTS
FOR (n:Playbook) REQUIRE n.id IS UNIQUE;

// ---- Performance indexes on commonly-filtered properties ----
CREATE INDEX host_name IF NOT EXISTS FOR (n:Host) ON (n.name);
CREATE INDEX asset_kind IF NOT EXISTS FOR (n:Asset) ON (n.kind);
CREATE INDEX asset_criticality IF NOT EXISTS FOR (n:Asset) ON (n.criticality);
CREATE INDEX ioc_type IF NOT EXISTS FOR (n:IOC) ON (n.ioc_type);
CREATE INDEX ioc_risk IF NOT EXISTS FOR (n:IOC) ON (n.risk_score);
CREATE INDEX incident_severity IF NOT EXISTS FOR (n:Incident) ON (n.severity);
CREATE INDEX incident_attack_type IF NOT EXISTS FOR (n:Incident) ON (n.attack_type);
CREATE INDEX threat_actor_name IF NOT EXISTS FOR (n:ThreatActor) ON (n.name);

// ---- Relationship indexes (speed up blast-radius traversal) ----
CREATE INDEX rel_compromised IF NOT EXISTS FOR ()-[r:COMPROMISED_BY]-() ON (r.since);
CREATE INDEX rel_logged_in IF NOT EXISTS FOR ()-[r:LOGGED_INTO]-() ON (r.at);
CREATE INDEX rel_targets IF NOT EXISTS FOR ()-[r:TARGETS]-() ON (r.since);

// ---- Full-text index over node names/values (free-text graph search) ----
CREATE FULLTEXT INDEX entity_search IF NOT EXISTS
FOR (n:User|Host|Asset|IP|Domain|ThreatActor|MalwareFamily)
ON EACH [n.name, n.value, n.id];
