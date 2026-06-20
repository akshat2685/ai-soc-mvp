"""Playbook memory module. Stores SOAR playbooks and manual procedures. Tracks
success/failure rates, execution time, and analyst feedback to automatically
recommend the best playbook for a given situation."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "playbooks"
_TYPE = MemoryType.PLAYBOOK.value


def record(playbook: dict[str, Any], source: str = "system") -> str:
    pb_id = playbook.get("id") or f"pb_{uuid.uuid4().hex[:10]}"
    row = {
        "id": pb_id,
        "name": playbook["name"],
        "steps": playbook.get("steps", []),
        "triggers": playbook.get("triggers", []),
        "success_rate": float(playbook.get("success_rate", 0.0)),
        "failure_rate": float(playbook.get("failure_rate", 0.0)),
        "avg_execution_sec": float(playbook.get("avg_execution_sec", 0.0)),
        "executions": int(playbook.get("executions", 0)),
        "analyst_feedback": playbook.get("analyst_feedback", []),
    }
    store.structured.upsert(_TABLE, "id", row)

    text = f"{row['name']} " + " ".join(str(t) for t in row.get("triggers", []))
    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{pb_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=pb_id,
        source=source,
        confidence=row["success_rate"],
        trust=0.7,
        impact=row["success_rate"],
        tags=["playbook"] + row.get("triggers", []),
        search_text=text,
    )
    store.graph.upsert_playbook(pb_id, name=row["name"])
    if text.strip():
        store.semantic.upsert_text(
            collection="playbooks",
            text=text,
            ref_type="playbook",
            ref_id=pb_id,
            confidence=row["success_rate"],
            payload={"success_rate": row["success_rate"], "triggers": row["triggers"]},
        )
    return pb_id


def record_execution(pb_id: str, *, success: bool, duration_sec: float, feedback: str = "") -> None:
    """Bump execution counts after a playbook run."""
    existing = store.structured.query(_TABLE, "id = %s", (pb_id,), limit=1)
    if not existing:
        return
    row = dict(existing[0])
    row["executions"] = int(row.get("executions", 0)) + 1
    n = row["executions"]
    if success:
        row["success_rate"] = round(((row["success_rate"] * (n - 1)) + 1.0) / n, 3)
    else:
        row["failure_rate"] = round(((row["failure_rate"] * (n - 1)) + 1.0) / n, 3)
    if duration_sec > 0:
        row["avg_execution_sec"] = round(
            ((row["avg_execution_sec"] * (n - 1)) + duration_sec) / n, 2
        )
    if feedback:
        fb = row.get("analyst_feedback") or []
        fb.append(feedback)
        row["analyst_feedback"] = fb[-20:]
    store.structured.upsert(_TABLE, "id", row)


def recommend(attack_type: str, top_k: int = 3) -> list[dict[str, Any]]:
    """Find best-matching playbooks by trigger overlap + success rate."""
    return store.structured.query(
        _TABLE,
        "triggers @> %s::text[]",
        ([attack_type],),
        limit=top_k,
    )


def list_all(limit: int = 100) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, limit=limit)
