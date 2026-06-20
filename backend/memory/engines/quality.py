"""Quality engine. Detects duplicate, conflicting, outdated, and low-confidence
knowledge so memory stays clean as it grows."""
from __future__ import annotations

import logging
from typing import Any

from .. import connections, store

log = logging.getLogger(__name__)


def find_duplicates(text: str, top_k: int = 5, threshold: float = 0.95) -> list[dict[str, Any]]:
    """Find near-duplicate memory objects via semantic similarity."""
    from ..store import semantic

    hits = semantic.search_all_collections(text, top_k=top_k)
    dups: list[dict[str, Any]] = []
    for coll, results in hits.items():
        for r in results:
            if r.get("score", 0) >= threshold:
                dups.append({"collection": coll, **r})
    return dups


def find_low_confidence(threshold: float = 0.3, limit: int = 50) -> list[dict[str, Any]]:
    """Memory objects with confidence below threshold."""
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, type, ref_table, ref_id, confidence FROM memory_objects "
            "WHERE confidence < %s AND is_persistent = FALSE ORDER BY confidence ASC LIMIT %s",
            (threshold, limit),
        )
        rows = cur.fetchall()
        cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]


def find_outdated(days: int = 180, limit: int = 50) -> list[dict[str, Any]]:
    """Memory objects not accessed in a long time and not persistent."""
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, type, ref_id, last_accessed FROM memory_objects "
            "WHERE last_accessed < now() - (%s || ' days')::interval "
            "AND is_persistent = FALSE ORDER BY last_accessed ASC LIMIT %s",
            (str(days), limit),
        )
        rows = cur.fetchall()
        cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]


def cleanup(threshold: float = 0.25, older_than_days: int = 365) -> dict:
    """Mark low-value memory for archival (never deletes — sets low importance)."""
    archived = 0
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE memory_objects
            SET importance = 0.0, impact = 0.0, updated_at = now()
            WHERE confidence < %s
              AND last_accessed < now() - (%s || ' days')::interval
              AND is_persistent = FALSE
            """,
            (threshold, str(older_than_days)),
        )
        archived = cur.rowcount
    log.info("Quality cleanup archived %d low-value objects.", archived)
    return {"archived": archived}
