"""Lessons learned memory module. After every incident, generate and store
permanent, searchable lessons: what happened, why, what worked/failed, and
recommendations."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "lessons_learned"
_TYPE = MemoryType.LESSON_LEARNED.value


def record(lesson: dict[str, Any], source: str = "system") -> str:
    ll_id = lesson.get("id") or f"ll_{uuid.uuid4().hex[:10]}"
    row = {
        "id": ll_id,
        "incident_id": lesson.get("incident_id"),
        "what_happened": lesson.get("what_happened"),
        "why_it_happened": lesson.get("why_it_happened"),
        "what_worked": lesson.get("what_worked"),
        "what_failed": lesson.get("what_failed"),
        "recommendations": lesson.get("recommendations", []),
    }
    store.structured.upsert(_TABLE, "id", row)

    text = " ".join(
        str(x) for x in [
            row.get("what_happened"), row.get("why_it_happened"),
            row.get("what_worked"), row.get("what_failed"),
        ] if x
    )
    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{ll_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=ll_id,
        source=source,
        confidence=0.8,
        trust=0.9,
        impact=0.7,
        tags=["lesson_learned"],
        search_text=text,
        is_persistent=True,
    )
    if text:
        store.semantic.upsert_text(
            collection="lessons_learned",
            text=text,
            ref_type="lesson",
            ref_id=ll_id,
            confidence=0.8,
            payload={"incident_id": row.get("incident_id")},
        )
    return ll_id


def find_relevant(text: str, top_k: int = 5) -> list[dict[str, Any]]:
    return store.semantic.search(collection="lessons_learned", query_text=text, top_k=top_k)


def list_all(limit: int = 100) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, limit=limit)
