"""Layer 4 — Temporal Memory.

Nothing is ever deleted. Every meaningful change to a memory object produces a
new version snapshot in `memory_versions`. The modules call `snapshot()` after
an update; older versions remain queryable for timeline generation and trend
analysis.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from .. import connections

log = logging.getLogger(__name__)


def snapshot(*, object_id: str, snapshot_data: dict[str, Any], changed_by: str = "system", reason: str = "") -> int:
    """Append a new version snapshot for a memory object. Returns version number."""
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(MAX(version), 0) FROM memory_versions WHERE object_id = %s",
            (object_id,),
        )
        last = cur.fetchone()[0] or 0
        version = last + 1
        cur.execute(
            """
            INSERT INTO memory_versions (object_id, version, changed_by, change_reason, snapshot)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (object_id, version, changed_by, reason, json.dumps(snapshot_data, default=str)),
        )
    return version


def history(object_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return all versions of a memory object, newest first."""
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT version, changed_by, change_reason, snapshot, created_at
            FROM memory_versions WHERE object_id = %s
            ORDER BY version DESC LIMIT %s
            """,
            (object_id, limit),
        )
        rows = cur.fetchall()
        cols = [d.name for d in cur.description]
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        try:
            d["snapshot"] = json.loads(d["snapshot"]) if isinstance(d["snapshot"], str) else d["snapshot"]
        except Exception:
            pass
        out.append(d)
    return out


def timeline(entity_filter: str = "", limit: int = 100) -> list[dict[str, Any]]:
    """Cross-object timeline: all version events, newest first."""
    where = "WHERE change_reason ILIKE %s" if entity_filter else ""
    params: tuple = (f"%{entity_filter}%", limit) if entity_filter else (limit,)
    sql = f"""
        SELECT object_id, version, changed_by, change_reason, created_at
        FROM memory_versions
        {where}
        ORDER BY created_at DESC LIMIT %s
    """
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
        cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]
