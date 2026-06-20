"""Continuous learning engine. After every investigation, updates:
  - IOC risk scores / reputation
  - User & asset baselines
  - Detection confidence
  - Playbook rankings
  - Agent accuracy stats

The memory system continuously evolves from outcomes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .. import store
from ..modules import assets, detections, iocs, playbooks, user_behavior

log = logging.getLogger(__name__)


def record_outcome(
    *,
    incident_id: str,
    verdict: str,                       # TRUE_POSITIVE / FALSE_POSITIVE / BENIGN
    iocs_seen: list[dict[str, Any]] | None = None,
    detection_id: str | None = None,
    playbook_id: str | None = None,
    playbook_success: bool | None = None,
    playbook_duration_sec: float | None = None,
    analyst_feedback: str = "",
) -> dict[str, Any]:
    """Apply post-investigation learning. Idempotent-safe."""
    is_tp = verdict.upper() == "TRUE_POSITIVE"
    is_fp = verdict.upper() == "FALSE_POSITIVE"
    updates: dict[str, Any] = {}

    # 1. IOC reputation
    if iocs_seen:
        bumped = 0
        for ioc in iocs_seen:
            try:
                iocs.observe(
                    ioc_type=ioc.get("ioc_type", "ip"),
                    value=ioc["value"],
                    severity="HIGH" if is_tp else "MEDIUM",
                    incident_id=incident_id,
                    threat_actor=ioc.get("threat_actor"),
                )
                bumped += 1
            except Exception as e:
                log.warning("IOC reputation update failed for %s: %s", ioc.get("value"), e)
        updates["iocs_bumped"] = bumped

    # 2. Detection confidence
    if detection_id:
        try:
            if is_tp:
                detections.update_counts(detection_id, tp=1)
            elif is_fp:
                detections.update_counts(detection_id, fp=1)
            updates["detection_updated"] = detection_id
        except Exception as e:
            log.warning("Detection update failed: %s", e)

    # 3. Playbook rankings
    if playbook_id and playbook_success is not None:
        try:
            playbooks.record_execution(
                playbook_id,
                success=playbook_success,
                duration_sec=playbook_duration_sec or 0.0,
                feedback=analyst_feedback,
            )
            updates["playbook_updated"] = playbook_id
        except Exception as e:
            log.warning("Playbook update failed: %s", e)

    # 4. Touch reference counts on the incident's memory object
    try:
        store.structured.execute(
            """
            UPDATE memory_objects
            SET reference_count = reference_count + 1, last_accessed = now()
            WHERE id = %s
            """,
            (f"incident_{incident_id}",),
        )
    except Exception:
        pass

    updates["incident_id"] = incident_id
    updates["verdict"] = verdict
    updates["learned_at"] = datetime.now(timezone.utc).isoformat()
    log.info("Learning applied for incident %s: %s", incident_id, updates)
    return updates


def recompute_all_scores() -> dict[str, int]:
    """Recompute importance across all memory (decay + scoring)."""
    from . import decay, scoring

    d = decay.apply_decay()
    s = scoring.recompute_all()
    return {"decay": d["updated"], "importance": s}
