"""Read-only HTTP client for the existing SOC.

The memory platform ingests knowledge from the SOC by hitting its existing
endpoints — NO edits to the SOC are required to populate memory. All calls are
read-only and fail soft: if the SOC is offline, methods return empty lists so
the memory platform keeps running.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .config import get_settings

log = logging.getLogger(__name__)
_settings = get_settings()

# Module-level client; reused across calls. httpx.Client is thread-safe.
_client: httpx.Client | None = None


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(base_url=_settings.soc_api_url, timeout=5.0)
    return _client


def _get(path: str, **params: Any) -> Any:
    try:
        resp = _get_client().get(path, params=params)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.debug("SOC GET %s failed: %s", path, e)
        return []


def is_reachable() -> bool:
    """Quick liveness probe of the SOC."""
    try:
        r = _get_client().get("/stats")
        return r.status_code == 200
    except Exception:
        return False


# --- Direct endpoint reads -------------------------------------------------
def get_alerts() -> list[dict[str, Any]]:
    return _get("/alerts") or []


def get_incidents() -> list[dict[str, Any]]:
    return _get("/incidents") or []


def get_responses() -> list[dict[str, Any]]:
    return _get("/responses") or []


def get_logs(limit: int = 500) -> list[dict[str, Any]]:
    return _get("/logs", limit=limit) or []


def get_stats() -> dict[str, Any]:
    return _get("/stats") or {}


def get_alert_details(alert_id: int) -> dict[str, Any]:
    return _get(f"/alerts/{alert_id}/details") or {}


def get_incident_details(incident_id: int | str) -> dict[str, Any]:
    return _get(f"/incidents/{incident_id}/details") or {}


def close() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
