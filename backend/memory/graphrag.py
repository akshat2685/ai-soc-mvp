"""GraphRAG — fuses Vector search (Qdrant) + Graph traversal (Neo4j) + Structured
queries (PostgreSQL) to produce enriched, relationship-aware investigations.

A plain RAG recall only finds documents that are textually similar. GraphRAG
ALSO expands the graph around every hit to pull in related entities (hosts an
IOC talked to, users a threat actor targeted, assets in the blast radius),
yielding far richer context than any single backend alone.
"""
from __future__ import annotations

import logging
from typing import Any

from . import store
from .store import graph as graph_store, semantic, structured

log = logging.getLogger(__name__)


def graphrag(query_text: str, *, top_k: int = 5, expand_hops: int = 2) -> dict[str, Any]:
    """Run a fused vector + graph + structured retrieval.

    Returns:
        {
          "query": ...,
          "vector_hits": [...],         # raw semantic hits across collections
          "expanded_entities": [...],   # graph neighbors of the hits
          "structured_matches": [...],  # direct PG matches
          "fused_context": str          # rendered text ready for an LLM
        }
    """
    # 1. Vector search across all semantic collections
    vector_hits = semantic.search_all_collections(query_text, top_k=top_k)

    # 2. Expand the graph around every entity value surfaced by the vector hits
    expanded: list[dict[str, Any]] = []
    seen_values: set[str] = set()
    for coll, hits in vector_hits.items():
        for h in hits:
            payload = h.get("payload", {})
            for field in ("value", "ref_id", "ip", "domain", "user_id"):
                val = payload.get(field)
                if val and val not in seen_values:
                    seen_values.add(str(val))
                    # Try IP first, then generic entity
                    for label, kf in (("IP", "value"), ("Domain", "value"), ("User", "id"), ("Host", "id")):
                        neighbors = _safe_blast(label, kf, str(val), expand_hops)
                        if neighbors:
                            expanded.append(
                                {"seed": str(val), "label": label, "neighbors": neighbors}
                            )
                            break

    # 3. Structured matches (trigram search in PG)
    structured_matches: list[dict[str, Any]] = []
    try:
        with structured.pg_conn() if hasattr(structured, "pg_conn") else _pg_ctx() as conn:
            pass
    except Exception:
        pass
    try:
        structured_matches = structured.query(
            "memory_objects",
            "search_text ILIKE %s",
            (f"%{query_text.split()[0]}%",),
            limit=5,
        )
    except Exception as e:
        log.warning("structured match failed: %s", e)

    # 4. Fuse into a single context block
    fused_lines: list[str] = [f"# GraphRAG Context — query: {query_text}"]
    total_vec = sum(len(h) for h in vector_hits.values())
    fused_lines.append(f"Vector hits: {total_vec} across {len(vector_hits)} collections")
    for coll, hits in vector_hits.items():
        for h in hits[:2]:
            fused_lines.append(f"- [{coll} score={h.get('score', 0):.2f}] {h.get('payload', {}).get('text', '')[:160]}")
    fused_lines.append("")
    fused_lines.append(f"Graph expansions: {len(expanded)} seed entities")
    for e in expanded[:5]:
        fused_lines.append(f"- Seed {e['label']}={e['seed']} -> {len(e['neighbors'])} neighbors")
        for n in e["neighbors"][:3]:
            fused_lines.append(
                f"    {n.get('from_label')} {n.get('from_id')} -[{n.get('rel')}]-> "
                f"{n.get('to_label')} {n.get('to_id')}"
            )
    fused_lines.append("")
    fused_lines.append(f"Structured matches: {len(structured_matches)}")

    return {
        "query": query_text,
        "vector_hits": vector_hits,
        "expanded_entities": expanded,
        "structured_matches": structured_matches,
        "fused_context": "\n".join(fused_lines),
    }


def _safe_blast(label: str, key_field: str, value: str, hops: int) -> list[dict[str, Any]]:
    try:
        return graph_store.blast_radius(label, key_field, value, max_hops=hops)
    except Exception:
        return []


def _pg_ctx():
    from .. import connections

    return connections.pg_conn()
