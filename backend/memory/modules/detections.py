"""Detection memory module. Stores detection rules (Sigma, YARA, custom, ML) and
tracks their quality metrics (TP/FP/FN/coverage/precision) over time so the
platform can recommend rule improvements."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "detections"
_TYPE = MemoryType.DETECTION.value


def record(detection: dict[str, Any], source: str = "system") -> str:
    det_id = detection.get("id") or f"det_{uuid.uuid4().hex[:10]}"
    tp = int(detection.get("true_positives", 0))
    fp = int(detection.get("false_positives", 0))
    fn = int(detection.get("false_negatives", 0))
    total = tp + fp
    precision = round(tp / total, 3) if total > 0 else 0.0
    coverage = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    row = {
        "id": det_id,
        "rule_type": detection.get("rule_type", "custom"),
        "logic": detection.get("logic"),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "coverage": coverage,
        "precision": precision,
    }
    store.structured.upsert(_TABLE, "id", row)

    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{det_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=det_id,
        source=source,
        confidence=precision,
        trust=0.6,
        impact=coverage,
        tags=["detection", row["rule_type"]],
        search_text=f"{row['rule_type']} rule precision={precision} coverage={coverage}",
    )
    store.temporal.snapshot(object_id=obj_id, snapshot_data=row, changed_by=source, reason="detection update")
    return det_id


def update_counts(det_id: str, *, tp: int = 0, fp: int = 0, fn: int = 0) -> None:
    existing = store.structured.query(_TABLE, "id = %s", (det_id,), limit=1)
    if not existing:
        return
    row = dict(existing[0])
    row["true_positives"] = row.get("true_positives", 0) + tp
    row["false_positives"] = row.get("false_positives", 0) + fp
    row["false_negatives"] = row.get("false_negatives", 0) + fn
    t = row["true_positives"]
    f = row["false_positives"]
    row["precision"] = round(t / (t + f), 3) if (t + f) > 0 else 0.0
    t2, f2 = t, row["false_negatives"]
    row["coverage"] = round(t2 / (t2 + f2), 3) if (t2 + f2) > 0 else 0.0
    store.structured.upsert(_TABLE, "id", row)


def list_all(limit: int = 100) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, limit=limit)
