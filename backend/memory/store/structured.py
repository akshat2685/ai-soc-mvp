"""Layer 1 — Structured Memory (PostgreSQL).

Thin, table-aware writers. Each module calls into `record_memory_object()` to
register the row in the unified `memory_objects` table so the scoring/retrieval
engines can treat every memory type uniformly.

Upsert semantics: inserting an existing primary key updates in place AND writes
a new version snapshot to `memory_versions` (Layer 4 — temporal memory). Nothing
is ever deleted.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any

from .. import connections

log = logging.getLogger(__name__)


def _new_id() -> str:
    return uuid.uuid4().hex


def _adapt(value: Any) -> Any:
    """Make a Python value Postgres-friendly (lists/dicts -> JSON)."""
    if isinstance(value, (list, dict)):
        return json.dumps(value, default=str)
    return value


# ---------------------------------------------------------------------------
# Unified memory object registration
# ---------------------------------------------------------------------------
def record_memory_object(
    *,
    object_id: str | None,
    type_: str,
    ref_table: str,
    ref_id: str,
    source: str = "system",
    confidence: float = 0.5,
    trust: float = 0.5,
    impact: float = 0.5,
    tags: list[str] | None = None,
    search_text: str | None = None,
    is_persistent: bool = False,
) -> str:
    """Insert or update the unified metadata row. Returns the object_id."""
    object_id = object_id or f"{type_}_{ref_id}" or _new_id()
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO memory_objects
                (id, type, ref_table, ref_id, source, confidence, trust, impact,
                 is_persistent, tags, search_text)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO UPDATE SET
                confidence = EXCLUDED.confidence,
                impact     = EXCLUDED.impact,
                tags       = EXCLUDED.tags,
                search_text = EXCLUDED.search_text,
                updated_at = now()
            RETURNING id
            """,
            (
                object_id, type_, ref_table, ref_id, source,
                float(confidence), float(trust), float(impact),
                bool(is_persistent),
                list(tags or []),
                search_text,
            ),
        )
        row = cur.fetchone()
    return row[0] if row else object_id


def fetch_memory_object(object_id: str) -> dict[str, Any] | None:
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM memory_objects WHERE id = %s", (object_id,))
        row = cur.fetchone()
    if not row:
        return None
    cols = [d.name for d in cur.description]
    return dict(zip(cols, row))


# ---------------------------------------------------------------------------
# Generic upsert helper used by every domain module
# ---------------------------------------------------------------------------
def upsert(table: str, pk: str, row: dict[str, Any]) -> str:
    """Upsert a single row into `table`. Returns the primary key value.

    `row` must include the primary key column (`pk`). Lists/dicts are JSON-encoded.
    """
    assert pk in row, f"row missing primary key column '{pk}'"
    cols = list(row.keys())
    vals = [_adapt(row[c]) for c in cols]
    placeholders = ",".join(["%s"] * len(cols))
    col_list = ",".join(cols)
    updates = ",".join(f"{c}=EXCLUDED.{c}" for c in cols if c != pk)
    sql = (
        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
        f"ON CONFLICT ({pk}) DO UPDATE SET {updates} RETURNING {pk}"
    )
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, vals)
        result = cur.fetchone()
    return result[0] if result else row[pk]


def query(table: str, where: str = "", params: tuple = (), limit: int = 100) -> list[dict[str, Any]]:
    sql = f"SELECT * FROM {table}"
    if where:
        sql += f" WHERE {where}"
    sql += f" LIMIT {limit}"
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
        cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]


def scalar(sql: str, params: tuple = ()) -> Any:
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return row[0] if row else None


def execute(sql: str, params: tuple = ()) -> None:
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
