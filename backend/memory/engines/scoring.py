"""Scoring engine.

importance = w_conf*confidence + w_trust*trust + w_recency*recency
           + w_usage*usage + w_impact*impact

All inputs/outputs are in [0,1]. Weights come from config (env-tunable).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .. import store
from ..config import get_settings

log = logging.getLogger(__name__)
_cfg = get_settings()


def compute_importance(confidence: float, trust: float, recency: float, usage: float, impact: float) -> float:
    w = _cfg.scoring
    importance = (
        w.confidence * confidence
        + w.trust * trust
        + w.recency * recency
        + w.usage * usage
        + w.impact * impact
    )
    return round(min(1.0, max(0.0, importance)), 4)


def recompute_object(object_id: str) -> float:
    """Read a memory_object's current sub-scores and persist the new importance."""
    obj = store.structured.fetch_memory_object(object_id)
    if not obj:
        return 0.0
    importance = compute_importance(
        obj["confidence"], obj["trust"], obj["recency"], obj["usage"], obj["impact"]
    )
    store.structured.execute(
        "UPDATE memory_objects SET importance = %s, updated_at = now() WHERE id = %s",
        (importance, object_id),
    )
    return importance


def recompute_all(batch: int = 500) -> int:
    """Recompute importance for every memory object. Returns count updated."""
    from .. import connections

    updated = 0
    with connections.pg_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM memory_objects ORDER BY updated_at ASC LIMIT %s", (batch,))
        ids = [r[0] for r in cur.fetchall()]
    for oid in ids:
        recompute_object(oid)
        updated += 1
    return updated


def usage_signal(reference_count: int) -> float:
    """Map reference_count to a [0,1] usage score (log-saturating)."""
    import math

    if reference_count <= 0:
        return 0.0
    return round(min(1.0, math.log1p(reference_count) / math.log1p(50)), 4)
