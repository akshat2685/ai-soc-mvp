"""Agent decisions memory module. Records every AI agent decision, reasoning,
tool call, and outcome so agents can self-improve via feedback loops."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "agent_decisions"
_TYPE = MemoryType.AGENT_DECISION.value


def record(decision: dict[str, Any], source: str = "system") -> str:
    ad_id = decision.get("id") or f"ad_{uuid.uuid4().hex[:10]}"
    row = {
        "id": ad_id,
        "agent_role": decision.get("agent_role", "investigation"),
        "decision": decision.get("decision"),
        "reasoning": decision.get("reasoning"),
        "tool_calls": decision.get("tool_calls", []),
        "outcome": decision.get("outcome"),
        "confidence": float(decision.get("confidence", 0.5)),
        "success": bool(decision.get("success", False)),
    }
    store.structured.upsert(_TABLE, "id", row)

    text = f"{row['agent_role']} decided: {row['decision']} — {row['reasoning']}"
    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{ad_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=ad_id,
        source=source,
        confidence=row["confidence"],
        trust=0.6,
        impact=0.6,
        tags=["agent_decision", row["agent_role"]],
        search_text=text,
    )
    store.temporal.snapshot(object_id=obj_id, snapshot_data=row, changed_by=source, reason="agent decision")
    return ad_id


def stats_by_role() -> dict[str, dict[str, float]]:
    """Success/total counts per agent role — the self-improvement signal."""
    rows = store.structured.query(_TABLE, "success IS NOT NULL", (), limit=100000)
    out: dict[str, dict[str, float]] = {}
    for r in rows:
        role = r.get("agent_role", "unknown")
        s = out.setdefault(role, {"success": 0.0, "total": 0.0})
        s["total"] += 1
        if r.get("success"):
            s["success"] += 1
    for v in out.values():
        v["accuracy"] = round(v["success"] / v["total"], 3) if v["total"] else 0.0
    return out
