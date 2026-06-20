"""Decay engine. Older memory loses influence over time — UNLESS it is:

  * frequently referenced (high usage), OR
  * high confidence, OR
  * high severity / impact, OR
  * recurring (seen again recently).

Critical knowledge persists indefinitely (is_persistent = TRUE).

The recency score halves every `DECAY_HALF_LIFE_DAYS` (default 90). Persistent
objects always get recency = 1.0.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone

from .. import connections
from ..config import get_settings

log = logging.getLogger(__name__)
_cfg = get_settings()


def _recency(last_accessed: datetime, is_persistent: bool, reference_count: int, severity_tag: str | None) -> float:
    if is_persistent:
        return 1.0
    # Persist-by-exception rules
    if reference_count >= 5:
        return 1.0
    if severity_tag and severity_tag.upper() in {"CRITICAL", "HIGH"}:
        return 1.0
    # Exponential decay
    age = datetime.now(timezone.utc) - last_accessed
    half_life = timedelta(days=_cfg.decay_half_life_days)
    if age <= timedelta(0):
        return 1.0
    ratio = age.total_seconds() / half_life.total_seconds()
    return round(max(0.0, math.pow(0.5, ratio)), 4)


def apply_decay(batch: int = 500) -> dict:
    """Recompute recency for a batch of memory objects. Returns counts."""
    updated = 0
    persisted = 0
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, last_accessed, is_persistent, reference_count, tags
            FROM memory_objects
            ORDER BY last_accessed ASC
            LIMIT %s
            """,
            (batch,),
        )
        rows = cur.fetchall()
        for oid, last, persistent, refs, tags in rows:
            sev = None
            if tags:
                for t in tags:
                    if t and t.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                        sev = t
                        break
            recency = _recency(last, persistent, refs or 0, sev)
            if persistent:
                persisted += 1
            cur.execute(
                "UPDATE memory_objects SET recency = %s, updated_at = now() WHERE id = %s",
                (recency, oid),
            )
            updated += 1
    log.info("Decay applied: %d updated (%d persistent).", updated, persisted)
    return {"updated": updated, "persistent": persisted, "batch": batch}
