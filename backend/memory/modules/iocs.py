"""IOC memory module. Stores indicators (IP, domain, URL, hash, email, registry
key, process). Computes a rolling risk score from times_seen, severity history,
and linked threat actors."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "iocs"
_TYPE = MemoryType.IOC.value

_SEVERITY_WEIGHTS = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}


def compute_risk(ioc: dict[str, Any]) -> float:
    """Risk score in [0,1]: blend of recency, frequency, severity, actor linkage."""
    severity_history = ioc.get("severity_history", []) or []
    sev_score = (
        max((_SEVERITY_WEIGHTS.get(s, 0.3) for s in severity_history), default=0.3)
        if severity_history
        else 0.3
    )
    freq = min(1.0, (int(ioc.get("times_seen", 1) or 1)) / 20.0)
    linked_actors = len(ioc.get("threat_actors_linked", []) or [])
    actor_score = min(1.0, linked_actors * 0.3)
    # Weighted blend
    risk = 0.45 * sev_score + 0.25 * freq + 0.30 * actor_score
    return round(min(1.0, max(0.0, risk)), 3)


def observe(
    *,
    ioc_type: str,
    value: str,
    severity: str = "MEDIUM",
    incident_id: str | None = None,
    threat_actor: str | None = None,
    source: str = "system",
) -> str:
    """Record (or bump) an IOC sighting. Updates times_seen, risk, history."""
    ioc_id = f"{ioc_type}_{value}"
    existing = store.structured.query(_TABLE, "ioc_type = %s AND value = %s", (ioc_type, value), limit=1)
    now = datetime.now(timezone.utc)
    if existing:
        e = existing[0]
        sev_history = e.get("severity_history") or []
        sev_history.append(severity)
        linked_actors = e.get("threat_actors_linked") or []
        if threat_actor and threat_actor not in linked_actors:
            linked_actors.append(threat_actor)
        incidents = e.get("incidents_linked") or []
        if incident_id and incident_id not in incidents:
            incidents.append(incident_id)
        times_seen = int(e.get("times_seen", 0)) + 1
        row = {
            "id": e["id"],
            "ioc_type": ioc_type,
            "value": value,
            "times_seen": times_seen,
            "incidents_linked": incidents,
            "threat_actors_linked": linked_actors,
            "severity_history": sev_history[-20:],   # keep last 20
            "resolution_history": e.get("resolution_history") or [],
            "risk_score": compute_risk(
                {"times_seen": times_seen, "severity_history": sev_history, "threat_actors_linked": linked_actors}
            ),
            "first_seen": e.get("first_seen") or now,
            "last_seen": now,
        }
    else:
        row = {
            "id": ioc_id,
            "ioc_type": ioc_type,
            "value": value,
            "times_seen": 1,
            "incidents_linked": [incident_id] if incident_id else [],
            "threat_actors_linked": [threat_actor] if threat_actor else [],
            "severity_history": [severity],
            "resolution_history": [],
            "risk_score": compute_risk(
                {"times_seen": 1, "severity_history": [severity], "threat_actors_linked": [threat_actor] if threat_actor else []}
            ),
            "first_seen": now,
            "last_seen": now,
        }
    store.structured.upsert(_TABLE, "id", row)

    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{ioc_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=ioc_id,
        source=source,
        confidence=min(1.0, 0.3 + row["risk_score"]),
        trust=0.6,
        impact=row["risk_score"],
        tags=[ioc_type, severity],
        search_text=f"{ioc_type} {value}",
        is_persistent=row["risk_score"] >= 0.7,
    )
    store.temporal.snapshot(
        object_id=obj_id, snapshot_data=row, changed_by=source, reason=f"ioc observed ({severity})"
    )

    # Graph: IP/Domain nodes for traversal
    if ioc_type == "ip":
        store.graph.upsert_ip(value, risk_score=row["risk_score"], last_seen=now.isoformat())
    elif ioc_type == "domain":
        store.graph.upsert_domain(value, risk_score=row["risk_score"])
    store.graph.upsert_ioc(ioc_id, ioc_type=ioc_type, value=value, risk_score=row["risk_score"])

    return ioc_id


def get(ioc_type: str, value: str) -> dict[str, Any] | None:
    rows = store.structured.query(_TABLE, "ioc_type = %s AND value = %s", (ioc_type, value), limit=1)
    return rows[0] if rows else None


def list_high_risk(min_risk: float = 0.7, limit: int = 50) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, "risk_score >= %s", (min_risk,), limit=limit)
