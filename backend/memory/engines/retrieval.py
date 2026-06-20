"""Retrieval engine — the 8-step pipeline.

When a new alert arrives this engine orchestrates a sweep across every memory
layer, then hands the assembled context to context_assembly for token-budgeted
rendering. The LLM should NEVER investigate without this context.

Steps:
  1. Search PostgreSQL (structured memory) by IP / user / asset keys
  2. Search Qdrant (semantic memory) for similar incidents & investigations
  3. Search Neo4j (relationship memory) for blast radius & related entities
  4. Rank & retrieve similar past incidents
  5. Retrieve related threat actors
  6. Retrieve relevant playbook recommendation
  7. Build context package
  8. Return LLM-ready context payload
"""
from __future__ import annotations

import logging
from typing import Any

from .. import soc_client, store
from ..modules import (
    assets,
    incidents,
    investigations,
    iocs,
    lessons_learned,
    playbooks,
)
from ..store import graph as graph_store
from ..schemas import AgentRole, ContextPackage, RecallRequest

log = logging.getLogger(__name__)


def _extract_keys(alert: dict[str, Any]) -> dict[str, Any]:
    """Pull the lookup keys out of an alert (be lenient about field names)."""
    ips = []
    for k in ("attacker_ip", "source_ip", "ip"):
        v = alert.get(k)
        if v:
            ips.append(v)
    users = [u for u in (alert.get("affected_users") or [alert.get("user_id")]) if u]
    return {
        "ips": [i for i in set(ips) if i],
        "users": [u for u in set(users) if u],
        "attack_type": alert.get("attack_type"),
        "title": alert.get("title"),
        "severity": (alert.get("severity") or "").upper(),
    }


# ---------------------------------------------------------------------------
# Step 1: PostgreSQL structured lookup
# ---------------------------------------------------------------------------
def _search_structured(keys: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"iocs": [], "assets": [], "related_incidents": []}
    try:
        for ip in keys["ips"]:
            row = iocs.get("ip", ip)
            if row:
                out["iocs"].append(row)
        for u in keys["users"]:
            ub = store.structured.query("user_behavior", "user_id = %s", (u,), limit=1)
            if ub:
                out.setdefault("user_behavior", []).extend(ub)
        # Incidents sharing the same attack type
        if keys["attack_type"]:
            out["related_incidents"] = store.structured.query(
                "incidents", "attack_type = %s", (keys["attack_type"],), limit=5
            )
    except Exception as e:
        log.warning("structured lookup failed: %s", e)
    return out


# ---------------------------------------------------------------------------
# Step 2: Qdrant semantic search
# ---------------------------------------------------------------------------
def _search_semantic(query_text: str, top_k: int) -> dict[str, list[dict[str, Any]]]:
    if not query_text:
        return {}
    try:
        return store.semantic.search_all_collections(query_text, top_k=top_k)
    except Exception as e:
        log.warning("semantic search failed: %s", e)
        return {}


# ---------------------------------------------------------------------------
# Step 3: Neo4j graph expansion
# ---------------------------------------------------------------------------
def _search_graph(keys: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"blast_radius": [], "related_threat_actors": []}
    try:
        for ip in keys["ips"]:
            out["blast_radius"].extend(graph_store.blast_radius("IP", "value", ip, max_hops=3))
            out["related_threat_actors"].extend(graph_store.find_related_threat_actors(ip))
        for u in keys["users"]:
            out["blast_radius"].extend(graph_store.blast_radius("User", "id", u, max_hops=3))
    except Exception as e:
        log.warning("graph search failed: %s", e)
    return out


# ---------------------------------------------------------------------------
# Step 4-6: ranked retrieval of incidents / threat actors / playbooks
# ---------------------------------------------------------------------------
def _rank_similar_incidents(semantic_hits: dict[str, list]) -> list[dict[str, Any]]:
    """Pull full incident rows for the top semantic hits in incident_reports."""
    ids = [
        h["payload"].get("ref_id")
        for h in semantic_hits.get("incident_reports", [])
        if h.get("payload", {}).get("ref_id")
    ]
    out: list[dict[str, Any]] = []
    for iid in ids[:5]:
        row = incidents.get(iid)
        if row:
            out.append(row)
    return out


def _recommend_playbook(attack_type: str | None) -> dict[str, Any] | None:
    if not attack_type:
        return None
    try:
        recs = playbooks.recommend(attack_type, top_k=1)
        return recs[0] if recs else None
    except Exception as e:
        log.warning("playbook recommend failed: %s", e)
        return None


def _relevant_lessons(query_text: str, top_k: int = 3) -> list[dict[str, Any]]:
    if not query_text:
        return []
    try:
        return lessons_learned.find_relevant(query_text, top_k=top_k)
    except Exception as e:
        log.warning("lessons retrieval failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Public API: the full pipeline
# ---------------------------------------------------------------------------
def recall(request: RecallRequest, *, skip_context_render: bool = False) -> ContextPackage:
    """Run all 8 steps and return a ContextPackage ready for an LLM."""
    alert = request.alert
    keys = _extract_keys(alert)

    # Build a natural-language query if none was supplied
    query_text = request.query_text or " ".join(
        str(x) for x in [keys.get("attack_type"), keys.get("title")] + keys["ips"] if x
    )

    sources: list[str] = []

    # Step 1 — Structured
    structured = _search_structured(keys)
    if structured.get("iocs") or structured.get("related_incidents"):
        sources.append("postgres")

    # Step 2 — Semantic
    semantic = _search_semantic(query_text, request.top_k)
    if any(semantic.values()):
        sources.append("qdrant")

    # Step 3 — Graph
    graph = _search_graph(keys)
    if graph.get("blast_radius") or graph.get("related_threat_actors"):
        sources.append("neo4j")

    # Step 4 — Rank similar incidents (from semantic hits)
    similar = _rank_similar_incidents(semantic)

    # Step 5 — Related threat actors (from graph)
    related_actors = graph.get("related_threat_actors", [])

    # Step 6 — Playbook recommendation
    recommended_pb = _recommend_playbook(keys["attack_type"])

    # Extra: lessons learned
    lessons = _relevant_lessons(query_text)

    pkg = ContextPackage(
        alert=alert,
        similar_incidents=similar,
        related_threat_actors=related_actors,
        related_iocs=structured.get("iocs", []),
        affected_assets=structured.get("assets", []),
        recommended_playbook=recommended_pb,
        graph_context=graph,
        blast_radius=graph.get("blast_radius", []),
        lessons=lessons,
        sources_queried=sources,
    )

    # Step 7 — Render LLM-ready context
    if not skip_context_render:
        from ..engines import context_assembly

        rendered, tokens = context_assembly.render(pkg, query_text=query_text)
        pkg.rendered_context = rendered
        pkg.token_estimate = tokens

    # Step 8 — package returned
    return pkg


def recall_from_soc_alert(alert_id: int, agent_role: AgentRole = AgentRole.TRIAGE) -> ContextPackage:
    """Convenience: pull an alert from the SOC over HTTP, then recall on it."""
    details = soc_client.get_alert_details(alert_id)
    alert = details.get("alert") if isinstance(details, dict) else {}
    if not alert:
        alert = {"id": alert_id}
    req = RecallRequest(alert=alert, agent_role=agent_role)
    return recall(req)
