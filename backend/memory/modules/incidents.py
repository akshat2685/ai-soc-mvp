"""Incident memory module.

Stores every incident (full version history, nothing deleted) and indexes it
for semantic recall + graph traversal. Called by the SOC integration whenever a
new incident is created.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)

_TABLE = "incidents"
_TYPE = MemoryType.INCIDENT.value


def record(incident: dict[str, Any], source: str = "system") -> str:
    """Create or update an incident record across all relevant layers.

    Required keys: id. Common keys: severity, attack_type, affected_assets,
    affected_users, investigation_summary, root_cause, response_actions,
    resolution, analyst_feedback, mitre_mapping.
    """
    inc_id = incident.get("id") or f"inc_{uuid.uuid4().hex[:12]}"
    row = {
        "id": inc_id,
        "severity": incident.get("severity"),
        "confidence": float(incident.get("confidence", 0.5)),
        "alert_source": incident.get("alert_source"),
        "attack_type": incident.get("attack_type"),
        "mitre_mapping": incident.get("mitre_mapping"),
        "affected_assets": incident.get("affected_assets", []),
        "affected_users": incident.get("affected_users", []),
        "investigation_summary": incident.get("investigation_summary"),
        "root_cause": incident.get("root_cause"),
        "response_actions": incident.get("response_actions", []),
        "resolution": incident.get("resolution"),
        "analyst_feedback": incident.get("analyst_feedback"),
        "verdict": incident.get("verdict", "PENDING"),
        "status": incident.get("status", "ACTIVE"),
        "correlation_key": incident.get("correlation_key"),
    }
    store.structured.upsert(_TABLE, "id", row)

    # Layer 5: unified metadata
    search_text = " | ".join(
        str(x) for x in [
            incident.get("attack_type"), incident.get("investigation_summary"),
            incident.get("root_cause"), incident.get("correlation_key"),
        ] if x
    )
    severity = (incident.get("severity") or "").upper()
    impact = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.5, "LOW": 0.25}.get(severity, 0.5)
    persistent = severity in {"CRITICAL", "HIGH"}
    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{inc_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=inc_id,
        source=source,
        confidence=float(incident.get("confidence", 0.5)),
        trust=0.7,
        impact=impact,
        tags=[incident.get("attack_type", ""), severity] if severity else [incident.get("attack_type", "")],
        search_text=search_text,
        is_persistent=persistent,
    )

    # Layer 4: temporal snapshot
    store.temporal.snapshot(
        object_id=obj_id, snapshot_data=incident, changed_by=source, reason="incident record"
    )

    # Layer 2: semantic (searchable summary)
    if search_text:
        store.semantic.upsert_text(
            collection="incident_reports",
            text=search_text,
            ref_type="incident",
            ref_id=inc_id,
            confidence=float(incident.get("confidence", 0.5)),
            severity=severity or None,
            payload={"attack_type": incident.get("attack_type")},
        )

    # Layer 3: graph node
    store.graph.upsert_incident(
        inc_id,
        severity=severity,
        attack_type=incident.get("attack_type"),
        status=incident.get("status", "ACTIVE"),
    )
    return inc_id


def get(incident_id: str) -> dict[str, Any] | None:
    rows = store.structured.query(_TABLE, "id = %s", (incident_id,), limit=1)
    return rows[0] if rows else None


def list_all(limit: int = 100) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, limit=limit)


def find_similar(text: str, top_k: int = 5) -> list[dict[str, Any]]:
    """Semantic search over incident reports."""
    return store.semantic.search(collection="incident_reports", query_text=text, top_k=top_k)
