"""Layer 3 — Relationship Memory (Neo4j).

Writes the cyber knowledge graph: nodes for entities (User, Host, IP, ...),
relationships describing how they interact, and incident-linked context used by
the GraphRAG engine for blast-radius / lateral-movement queries.
"""
from __future__ import annotations

import logging
from typing import Any

from .. import connections

log = logging.getLogger(__name__)


def _run(cypher: str, **params: Any) -> list[dict[str, Any]]:
    with connections.get_neo4j().session() as s:
        result = s.run(cypher, **params)
        records = [dict(r) for r in result]
        result.consume()
    return records


# ---------------------------------------------------------------------------
# Node upserts (MERGE keeps it idempotent)
# ---------------------------------------------------------------------------
def upsert_node(label: str, key_field: str, key_value: str, **props: Any) -> None:
    """MERGE a node by its unique key, then set the extra properties."""
    safe_label = label.replace("`", "")
    # Build SET clause for properties
    set_parts = [f"n.{k} = $p_{k}" for k in props]
    set_clause = (" SET " + ", ".join(set_parts)) if set_parts else ""
    params = {f"p_{k}": v for k, v in props.items()}
    params["kv"] = key_value
    _run(
        f"MERGE (n:`{safe_label}` {{{key_field}: $kv}})" + set_clause,
        **params,
    )


def upsert_ip(ip: str, **props: Any) -> None:
    upsert_node("IP", "value", ip, **props)


def upsert_domain(domain: str, **props: Any) -> None:
    upsert_node("Domain", "value", domain, **props)


def upsert_user(user_id: str, **props: Any) -> None:
    upsert_node("User", "id", user_id, **props)


def upsert_host(host_id: str, name: str | None = None, **props: Any) -> None:
    upsert_node("Host", "id", host_id, name=name or host_id, **props)


def upsert_asset(asset_id: str, kind: str, **props: Any) -> None:
    upsert_node("Asset", "id", asset_id, kind=kind, **props)


def upsert_threat_actor(actor_id: str, name: str, **props: Any) -> None:
    upsert_node("ThreatActor", "id", actor_id, name=name, **props)


def upsert_incident(incident_id: str, **props: Any) -> None:
    upsert_node("Incident", "id", incident_id, **props)


def upsert_ioc(ioc_id: str, ioc_type: str, value: str, risk_score: float = 0.0, **props: Any) -> None:
    upsert_node("IOC", "id", ioc_id, ioc_type=ioc_type, value=value, risk_score=risk_score, **props)


def upsert_playbook(playbook_id: str, name: str, **props: Any) -> None:
    upsert_node("Playbook", "id", playbook_id, name=name, **props)


# ---------------------------------------------------------------------------
# Relationship upserts
# ---------------------------------------------------------------------------
_REL_TEMPLATES = {
    "LOGGED_INTO":      ("User", "id", "Host", "id"),
    "CONNECTED_TO":     ("IP", "value", "IP", "value"),
    "COMMUNICATED_WITH":("Host", "id", "Host", "id"),
    "COMPROMISED_BY":   ("Host", "id", "ThreatActor", "id"),
    "BELONGS_TO":       ("Host", "id", "Asset", "id"),
    "TARGETS":          ("ThreatActor", "id", "Host", "id"),
    "OWNS":             ("User", "id", "Asset", "id"),
    "RESOLVES_TO":      ("Domain", "value", "IP", "value"),
    "EXECUTED":         ("Host", "id", "Process", "id"),
    "LINKED_TO_INCIDENT": (None, None, "Incident", "id"),
}


def link(
    rel_type: str,
    *,
    from_label: str,
    from_key_field: str,
    from_key_value: str,
    to_label: str,
    to_key_field: str,
    to_key_value: str,
    **props: Any,
) -> None:
    """MERGE a relationship between two existing nodes + set properties."""
    set_parts = [f"r.{k} = $p_{k}" for k in props]
    set_clause = (" SET " + ", ".join(set_parts)) if set_parts else ""
    params = {f"p_{k}": v for k, v in props.items()}
    params.update(fkv=from_key_value, tkv=to_key_value)
    cypher = (
        f"MATCH (a:`{from_label}` {{{from_key_field}: $fkv}}), "
        f"(b:`{to_label}` {{{to_key_field}: $tkv}}) "
        f"MERGE (a)-[r:`{rel_type}`]->(b){set_clause}"
    )
    _run(cypher, **params)


# ---------------------------------------------------------------------------
# Graph queries used by retrieval / GraphRAG
# ---------------------------------------------------------------------------
def blast_radius(entity_label: str, key_field: str, key_value: str, max_hops: int = 3) -> list[dict[str, Any]]:
    """Find everything reachable from an entity within `max_hops` (lateral movement / blast radius)."""
    cypher = (
        f"MATCH p=(start:`{entity_label}` {{{key_field}: $kv}})-[*1..{int(max_hops)}]-(related) "
        "WITH nodes(p) AS ns, relationships(p) AS rs "
        "UNWIND RANGE(0, size(ns)-2) AS i "
        "RETURN ns[i].__-(?) AS from_node, type(rs[i]) AS rel, ns[i+1] AS to_node "
        "LIMIT 50"
    )
    # Neo4j doesn't allow __-(?); do it with simpler projection
    cypher = (
        f"MATCH p=(start:`{entity_label}` {{{key_field}: $kv}})-[*1..{int(max_hops)}]-(related) "
        "UNWIND relationships(p) AS r WITH r, startNode(r) AS a, endNode(r) AS b "
        "RETURN labels(a)[0] AS from_label, coalesce(a.name, a.value, a.id) AS from_id, "
        "type(r) AS rel, labels(b)[0] AS to_label, coalesce(b.name, b.value, b.id) AS to_id, "
        "b.criticality AS criticality "
        "LIMIT 50"
    )
    return _run(cypher, kv=key_value)


def find_related_threat_actors(entity_value: str) -> list[dict[str, Any]]:
    """Which threat actors (if any) have been linked to this entity value?"""
    cypher = (
        "MATCH (a)-[:COMPROMISED_BY|TARGETS*1..2]-(ta:ThreatActor) "
        "WHERE coalesce(a.name, a.value, a.id) = $v "
        "RETURN DISTINCT ta.id AS id, ta.name AS name, labels(ta) AS labels "
        "LIMIT 20"
    )
    return _run(cypher, v=entity_value)


def shortest_path(from_label: str, from_kv: str, to_label: str, to_kv: str, key_field: str = "id") -> list[dict[str, Any]]:
    try:
        # Avoid f-string brace-escaping issues; Cypher uses literal {} for property maps.
        cypher = (
            "MATCH p = shortestPath("
            "(a:`" + from_label + "` {" + key_field + ": $a})-[*..6]-(b:`" + to_label + "` {" + key_field + ": $b})"
            ") "
            "UNWIND relationships(p) AS r WITH r, startNode(r) AS s, endNode(r) AS e "
            "RETURN coalesce(s.name, s.value, s.id) AS from_node, type(r) AS rel, "
            "coalesce(e.name, e.value, e.id) AS to_node LIMIT 20"
        )
        return _run(cypher, a=from_kv, b=to_kv)
    except Exception as e:
        log.warning("shortest_path query failed: %s", e)
        return []


def stats() -> dict[str, int]:
    rows = _run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS c")
    return {r["label"]: r["c"] for r in rows}
