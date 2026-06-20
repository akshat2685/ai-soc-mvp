"""User behavior memory module. Maintains behavioral baselines per user and
tracks drift over time so anomalies can be detected."""
from __future__ import annotations

import logging
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "user_behavior"
_TYPE = MemoryType.USER_BEHAVIOR.value


def record_observation(user_id: str, observation: dict[str, Any], source: str = "system") -> str:
    """Update a user's behavioral baseline with new observation data.

    Keys: typical_login_hour_utc, typical_location, typical_devices,
    typical_apps, typical_activity_level, baseline (dict), drift_score.
    """
    existing = store.structured.query(_TABLE, "user_id = %s", (user_id,), limit=1)
    if existing:
        row = dict(existing[0])
        row.update({k: observation[k] for k in observation if k != "user_id"})
    else:
        row = {"user_id": user_id, **observation}
    store.structured.upsert(_TABLE, "user_id", row)

    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{user_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=user_id,
        source=source,
        confidence=0.7,
        trust=0.6,
        impact=0.5,
        tags=["user_behavior"],
        search_text=f"user {user_id} baseline drift={row.get('drift_score', 0)}",
    )
    store.graph.upsert_user(user_id, drift_score=row.get("drift_score", 0))
    return user_id


def get_baseline(user_id: str) -> dict[str, Any] | None:
    rows = store.structured.query(_TABLE, "user_id = %s", (user_id,), limit=1)
    return rows[0] if rows else None


def list_drifting(min_drift: float = 0.5, limit: int = 50) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, "drift_score >= %s", (min_drift,), limit=limit)
