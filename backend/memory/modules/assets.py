"""Asset memory module. Tracks servers, endpoints, databases, apps, containers,
cloud resources. Computes asset risk scores from criticality + vulnerabilities +
incident history."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "assets"
_TYPE = MemoryType.ASSET.value

_CRITICALITY_WEIGHTS = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.5, "LOW": 0.25}


def compute_asset_risk(asset: dict[str, Any]) -> float:
    crit = _CRITICALITY_WEIGHTS.get((asset.get("criticality") or "").upper(), 0.5)
    vuln_score = min(1.0, len(asset.get("vulnerabilities", []) or []) * 0.15)
    inc_score = min(1.0, len(asset.get("incident_history", []) or []) * 0.1)
    return round(min(1.0, 0.5 * crit + 0.3 * vuln_score + 0.2 * inc_score), 3)


def record(asset: dict[str, Any], source: str = "system") -> str:
    asset_id = asset.get("id") or f"asset_{uuid.uuid4().hex[:10]}"
    row = {
        "id": asset_id,
        "name": asset.get("name", asset_id),
        "kind": asset.get("kind", "server"),
        "criticality": asset.get("criticality", "MEDIUM"),
        "owner": asset.get("owner"),
        "vulnerabilities": asset.get("vulnerabilities", []),
        "patch_history": asset.get("patch_history", []),
        "incident_history": asset.get("incident_history", []),
        "risk_score": compute_asset_risk(asset),
    }
    store.structured.upsert(_TABLE, "id", row)

    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{asset_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=asset_id,
        source=source,
        confidence=0.7,
        trust=0.7,
        impact=row["risk_score"],
        tags=["asset", row["kind"], row["criticality"]],
        search_text=f"{row['kind']} {row['name']} criticality={row['criticality']}",
        is_persistent=row["criticality"] in {"CRITICAL", "HIGH"},
    )
    store.graph.upsert_asset(asset_id, kind=row["kind"], criticality=row["criticality"], name=row["name"])
    return asset_id


def get(asset_id: str) -> dict[str, Any] | None:
    rows = store.structured.query(_TABLE, "id = %s", (asset_id,), limit=1)
    return rows[0] if rows else None


def list_high_risk(min_risk: float = 0.6, limit: int = 50) -> list[dict[str, Any]]:
    return store.structured.query(_TABLE, "risk_score >= %s", (min_risk,), limit=limit)
