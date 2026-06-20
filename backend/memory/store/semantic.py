"""Layer 2 — Semantic Memory (Qdrant).

Upserts text documents as vectors so the retrieval engine can answer questions
like "find all incidents similar to 'credential stuffing against VPN users'".

Collections (created by migrations.apply.ensure_qdrant_collections):
    soc_incident_reports, soc_investigation_notes, soc_threat_reports,
    soc_lessons_learned, soc_playbooks, soc_analyst_notes
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from qdrant_client.http import models as qm

from .. import connections, embeddings
from ..config import get_settings

log = logging.getLogger(__name__)
_cfg = get_settings()


def _collection(name: str) -> str:
    return _cfg.qdrant.collection(name)


def upsert_text(
    *,
    collection: str,
    text: str,
    ref_type: str,
    ref_id: str,
    confidence: float = 0.5,
    severity: str | None = None,
    timestamp: float | None = None,
    payload: dict[str, Any] | None = None,
    point_id: str | None = None,
) -> str:
    """Embed `text` and store it in `collection`. Returns the point id."""
    cname = _collection(collection)
    point_id = point_id or f"{ref_type}_{ref_id}" or uuid.uuid4().hex
    vector = embeddings.embed(text)
    store_payload = {
        "ref_type": ref_type,
        "ref_id": str(ref_id),
        "confidence": float(confidence),
        "severity": severity,
        "timestamp": timestamp,
        "text": text,
        **(payload or {}),
    }
    connections.get_qdrant().upsert(
        collection_name=cname,
        points=[qm.PointStruct(id=point_id, vector=vector, payload=store_payload)],
    )
    return point_id


def upsert_batch(
    *, collection: str, items: list[dict[str, Any]]
) -> int:
    """Bulk upsert. Each item needs at least: text, ref_type, ref_id."""
    cname = _collection(collection)
    texts = [it["text"] for it in items]
    if not texts:
        return 0
    vectors = embeddings.embed_batch(texts)
    points = []
    for it, vec in zip(items, vectors):
        pid = it.get("point_id") or f"{it['ref_type']}_{it['ref_id']}"
        points.append(
            qm.PointStruct(
                id=pid,
                vector=vec,
                payload={
                    "ref_type": it["ref_type"],
                    "ref_id": str(it["ref_id"]),
                    "confidence": float(it.get("confidence", 0.5)),
                    "severity": it.get("severity"),
                    "timestamp": it.get("timestamp"),
                    "text": it["text"],
                    **(it.get("payload") or {}),
                },
            )
        )
    connections.get_qdrant().upsert(collection_name=cname, points=points)
    return len(points)


def search(
    *,
    collection: str,
    query_text: str,
    top_k: int = 5,
    score_threshold: float = 0.0,
) -> list[dict[str, Any]]:
    """Semantic search. Returns list of {score, payload} dicts."""
    cname = _collection(collection)
    vector = embeddings.embed(query_text)
    try:
        hits = connections.get_qdrant().query_points(
            collection_name=cname,
            query=vector,
            limit=top_k,
            score_threshold=score_threshold,
        ).points
    except Exception as e:
        log.warning("Qdrant search on %s failed: %s", cname, e)
        return []
    return [{"score": float(h.score), "payload": h.payload or {}} for h in hits]


def search_all_collections(
    query_text: str, top_k: int = 3, collections: list[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Run the same query against every (or selected) collection."""
    names = collections or [
        "incident_reports",
        "investigation_notes",
        "threat_reports",
        "lessons_learned",
        "playbooks",
        "analyst_notes",
    ]
    out: dict[str, list[dict[str, Any]]] = {}
    for n in names:
        out[n] = search(collection=n, query_text=query_text, top_k=top_k)
    return out


def count(collection: str) -> int:
    cname = _collection(collection)
    try:
        r = connections.get_qdrant().count(collection_name=cname, exact=True)
        return r.count
    except Exception:
        return 0
