"""False positive memory module. Stores every false positive so the platform
can suppress repeated FPs and reduce analyst fatigue."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "false_positives"
_TYPE = MemoryType.FALSE_POSITIVE.value


def record(fp: dict[str, Any], source: str = "system") -> str:
    fp_id = fp.get("id") or f"fp_{uuid.uuid4().hex[:10]}"
    supp_key = fp.get("suppression_key") or f"{fp.get('detection_trigger','')}".lower()
    row = {
        "id": fp_id,
        "detection_trigger": fp.get("detection_trigger"),
        "investigation_outcome": fp.get("investigation_outcome"),
        "reason": fp.get("reason"),
        "suppression_key": supp_key,
    }
    store.structured.upsert(_TABLE, "id", row)

    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{fp_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=fp_id,
        source=source,
        confidence=0.6,
        trust=0.7,
        impact=0.3,
        tags=["false_positive"],
        search_text=f"{row['detection_trigger']} {row['reason']}",
    )
    return fp_id


def should_suppress(detection_trigger: str) -> bool:
    """Check if a detection trigger has been repeatedly marked FP."""
    key = (detection_trigger or "").lower()
    count = store.structured.scalar(
        "SELECT COUNT(*) FROM false_positives WHERE suppression_key = %s",
        (key,),
    )
    return bool(count and int(count) >= 2)


def list_all(limit: int = 100) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, limit=limit)
