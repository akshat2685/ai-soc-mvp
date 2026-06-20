"""Investigation memory module. Stores evidence, reasoning, conclusions, and
recommended actions. Enables 'find similar investigations' for new cases."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "investigations"
_TYPE = MemoryType.INVESTIGATION.value


def record(investigation: dict[str, Any], source: str = "system") -> str:
    inv_id = investigation.get("id") or f"inv_{uuid.uuid4().hex[:12]}"
    incident_id = investigation.get("incident_id")
    row = {
        "id": inv_id,
        "incident_id": incident_id,
        "evidence": investigation.get("evidence", []),
        "artifacts": investigation.get("artifacts", []),
        "logs": investigation.get("logs", []),
        "queries": investigation.get("queries", []),
        "reasoning_steps": investigation.get("reasoning_steps", []),
        "conclusions": investigation.get("conclusions", []),
        "recommended_actions": investigation.get("recommended_actions", []),
        "summary_text": investigation.get("summary_text"),
    }
    store.structured.upsert(_TABLE, "id", row)

    summary = investigation.get("summary_text") or " ".join(
        str(c) for c in investigation.get("conclusions", [])
    )
    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{inv_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=inv_id,
        source=source,
        confidence=0.7,
        trust=0.7,
        impact=0.6,
        tags=["investigation"],
        search_text=summary,
    )
    store.temporal.snapshot(object_id=obj_id, snapshot_data=investigation, changed_by=source, reason="investigation")
    if summary:
        store.semantic.upsert_text(
            collection="investigation_notes",
            text=summary,
            ref_type="investigation",
            ref_id=inv_id,
            confidence=0.7,
            payload={"incident_id": incident_id},
        )
    return inv_id


def find_similar(text: str, top_k: int = 5) -> list[dict[str, Any]]:
    return store.semantic.search(collection="investigation_notes", query_text=text, top_k=top_k)


def list_all(limit: int = 100) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, limit=limit)
