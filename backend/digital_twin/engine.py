"""Cyber Digital Twin Engine - Graph queries and models.

Allows querying and modeling the enterprise cyber assets, hosts, users, services,
cloud resources, trust relationships, and network topology in Neo4j.
"""
from __future__ import annotations

import logging
from typing import Any, List, Dict, Optional
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

# Try to import Neo4j connection safely
try:
    from backend.memory.connections import get_neo4j
except ImportError:
    get_neo4j = None


# ---------------------------------------------------------------------------
# Pydantic models for Digital Twin components
# ---------------------------------------------------------------------------
class AssetModel(BaseModel):
    id: str
    hostname: str
    ip: str
    os: str
    criticality: str = "Medium"
    owner: str = "Unknown"
    dept: str = "General"


class HostModel(BaseModel):
    id: str
    name: str
    ip: str
    os: str
    status: str = "ACTIVE"
    is_simulated: bool = False


class UserModel(BaseModel):
    id: str
    name: str
    dept: str = "General"
    risk_score: float = 0.5
    is_simulated: bool = False


class ServiceModel(BaseModel):
    id: str
    name: str
    port: int
    host_id: str


class CloudResourceModel(BaseModel):
    id: str
    name: str
    type: str  # e.g., s3_bucket, ec2_instance, gcs_bucket, rds
    provider: str = "AWS"


class TrustRelationship(BaseModel):
    from_id: str
    to_id: str
    trust_level: float = 0.5  # [0, 1] weight of trust
    description: str = "Default relationship"


class NetworkTopology(BaseModel):
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Neo4j query helper
# ---------------------------------------------------------------------------
def run_cypher(cypher: str, **params: Any) -> List[Dict[str, Any]]:
    """Run a cypher query against Neo4j, fail-soft if Neo4j is offline."""
    if not get_neo4j:
        log.warning("Neo4j connection not imported (degraded mode)")
        return []
    try:
        driver = get_neo4j()
        if not driver:
            log.warning("Neo4j driver is None (degraded mode)")
            return []
        with driver.session() as session:
            result = session.run(cypher, **params)
            records = [dict(r) for r in result]
            session.run("COMMIT").consume() # Ensure consumed/committed
            return records
    except Exception as e:
        log.warning("Neo4j cypher query failed (degraded mode): %s", e)
        return []


# ---------------------------------------------------------------------------
# Digital Twin algorithms
# ---------------------------------------------------------------------------
def calculate_blast_radius(entity_label: str, key_value: str, max_hops: int = 3) -> List[Dict[str, Any]]:
    """Finds all assets, users, and hosts reachable from a starting node.

    Used to measure the potential spread of lateral movement from a compromised node.
    """
    # Coalesce start key to check common fields like id, value, or name
    cypher = (
        f"MATCH p=(start:`{entity_label}`)-[*1..{int(max_hops)}]-(related) "
        "WHERE (start.id = $kv OR start.value = $kv OR start.name = $kv) "
        "UNWIND relationships(p) AS r WITH r, startNode(r) AS a, endNode(r) AS b "
        "RETURN labels(a)[0] AS from_label, "
        "       coalesce(a.name, a.value, a.id) AS from_id, "
        "       type(r) AS rel, "
        "       labels(b)[0] AS to_label, "
        "       coalesce(b.name, b.value, b.id) AS to_id, "
        "       b.criticality AS criticality, "
        "       r.is_simulated AS is_simulated "
        "LIMIT 100"
    )
    return run_cypher(cypher, kv=key_value)


def find_attack_paths(from_id: str, to_id: str) -> List[Dict[str, Any]]:
    """Finds the shortest attack path between two entities in the graph.

    Useful to understand how an attacker can navigate from an entry point to a critical target.
    """
    cypher = (
        "MATCH p = shortestPath((start)-[*..6]-(target)) "
        "WHERE (start.id = $from_id OR start.value = $from_id OR start.name = $from_id) "
        "  AND (target.id = $to_id OR target.value = $to_id OR target.name = $to_id) "
        "UNWIND relationships(p) AS r WITH r, startNode(r) AS s, endNode(r) AS e "
        "RETURN labels(s)[0] AS from_label, coalesce(s.name, s.value, s.id) AS from_id, "
        "       type(r) AS rel, labels(e)[0] AS to_label, coalesce(e.name, e.value, e.id) AS to_id, "
        "       r.trust_level AS weight "
        "LIMIT 50"
    )
    return run_cypher(cypher, from_id=from_id, to_id=to_id)


def calculate_critical_asset_exposure() -> List[Dict[str, Any]]:
    """Identifies any pathways from low-security or internet-facing nodes to Critical/High criticality assets."""
    cypher = (
        "MATCH (start) WHERE start.internet_facing = true OR start.internet_facing = 1 "
        "MATCH (target) WHERE target.criticality IN ['Critical', 'High', 'CRITICAL', 'HIGH'] "
        "MATCH p = shortestPath((start)-[*..4]-(target)) "
        "UNWIND relationships(p) AS r WITH r, startNode(r) AS s, endNode(r) AS e "
        "RETURN labels(s)[0] AS from_label, coalesce(s.name, s.value, s.id) AS from_id, "
        "       type(r) AS rel, labels(e)[0] AS to_label, coalesce(e.name, e.value, e.id) AS to_id, "
        "       e.criticality AS target_criticality "
        "LIMIT 100"
    )
    return run_cypher(cypher)


def get_network_topology() -> NetworkTopology:
    """Retrieve full network topology (nodes and edges) for visual representation."""
    nodes_cypher = "MATCH (n) RETURN id(n) as element_id, labels(n)[0] as label, properties(n) as props LIMIT 300"
    edges_cypher = "MATCH (a)-[r]->(b) RETURN id(r) as element_id, id(a) as source, id(b) as target, type(r) as type, properties(r) as props LIMIT 500"
    
    nodes_raw = run_cypher(nodes_cypher)
    edges_raw = run_cypher(edges_cypher)
    
    nodes = []
    for n in nodes_raw:
        props = n.get("props", {})
        nodes.append({
            "id": str(props.get("id") or props.get("value") or n.get("element_id")),
            "label": n.get("label", "Entity"),
            "properties": props
        })
        
    edges = []
    for e in edges_raw:
        edges.append({
            "id": str(e.get("element_id")),
            "source": str(e.get("source")),
            "target": str(e.get("target")),
            "type": e.get("type", "CONNECTED_TO"),
            "properties": e.get("props", {})
        })
        
    return NetworkTopology(nodes=nodes, edges=edges)
