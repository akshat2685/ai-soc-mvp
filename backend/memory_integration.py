"""Bridge between the existing SOC and the memory platform.

This module is the ONLY place the SOC needs to call. It is fail-soft: every
function catches its own errors so memory can NEVER break the SOC. The SOC can
import it and call `recall_and_enrich(alert)` inside its existing investigation
endpoint — or simply ignore it and the SOC keeps working as before.

Design choice: we keep this OUT of the memory package so the memory platform
remains a self-contained subsystem. The SOC owns the integration point.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


def recall_and_enrich(alert: dict[str, Any]) -> dict[str, Any]:
    """Return the memory-context package for an alert, or {} on any failure.

    Drop-in usage in the SOC's /alerts/{id}/investigate endpoint:

        from memory_integration import recall_and_enrich
        memory_ctx = recall_and_enrich(alert)   # never raises
        # ...then prepend memory_ctx["rendered_context"] to the LLM prompt
    """
    try:
        from backend.memory.engines import retrieval
        from backend.memory.schemas import RecallRequest

        req = RecallRequest(alert=alert)
        pkg = retrieval.recall(req)
        return pkg.model_dump()
    except Exception as e:
        log.warning("memory recall failed (degraded mode): %s", e)
        return {"error": str(e), "rendered_context": "", "degraded": True}


def ingest_incident_from_soc(incident: dict[str, Any]) -> str | None:
    """Push a SOC incident into memory. Returns memory id or None on failure."""
    try:
        from backend.memory.modules import incidents as incidents_module

        return incidents_module.record(incident, source="soc")
    except Exception as e:
        log.warning("memory incident ingest failed: %s", e)
        return None


def record_outcome(
    incident_id: str, verdict: str, iocs_seen: list[dict[str, Any]] | None = None, **kwargs
) -> dict[str, Any]:
    """Record an investigation outcome so the platform learns from it."""
    try:
        from backend.memory.engines import learning

        return learning.record_outcome(
            incident_id=incident_id, verdict=verdict, iocs_seen=iocs_seen or [], **kwargs
        )
    except Exception as e:
        log.warning("memory learning failed: %s", e)
        return {"error": str(e)}
