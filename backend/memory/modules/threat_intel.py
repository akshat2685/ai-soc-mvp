"""Threat intelligence memory module. Covers threat actors, campaigns, and
malware families. Tracks first/last seen, frequency, confidence, and source
reliability. Computes IOC reputation via the iocs module."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TYPE = MemoryType.THREAT_INTEL.value


def record_actor(actor: dict[str, Any], source: str = "system") -> str:
    aid = actor.get("id") or f"ta_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc)
    first = actor.get("first_seen") or now
    last = actor.get("last_seen") or now
    row = {
        "id": aid,
        "name": actor["name"],
        "aliases": actor.get("aliases", []),
        "ttps": actor.get("ttps", []),
        "first_seen": first,
        "last_seen": last,
        "frequency": int(actor.get("frequency", 1)),
        "confidence": float(actor.get("confidence", 0.7)),
        "source_reliability": float(actor.get("source_reliability", 0.7)),
        "description": actor.get("description"),
    }
    store.structured.upsert("threat_actors", "id", row)
    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_actor_{aid}",
        type_=_TYPE,
        ref_table="threat_actors",
        ref_id=aid,
        source=source,
        confidence=row["confidence"],
        trust=row["source_reliability"],
        impact=0.8,
        tags=["threat_actor", row["name"]],
        search_text=f"{row['name']} {row.get('description','')}",
        is_persistent=True,
    )
    store.temporal.snapshot(object_id=obj_id, snapshot_data=actor, changed_by=source, reason="threat actor")
    store.graph.upsert_threat_actor(aid, name=row["name"], description=row.get("description"))
    if row.get("description"):
        store.semantic.upsert_text(
            collection="threat_reports", text=f"{row['name']}: {row['description']}",
            ref_type="threat_actor", ref_id=aid, confidence=row["confidence"],
            severity="HIGH", payload={"aliases": row.get("aliases")},
        )
    return aid


def record_campaign(campaign: dict[str, Any], source: str = "system") -> str:
    cid = campaign.get("id") or f"camp_{uuid.uuid4().hex[:10]}"
    row = {
        "id": cid,
        "name": campaign["name"],
        "threat_actor": campaign.get("threat_actor"),
        "first_seen": campaign.get("first_seen") or datetime.now(timezone.utc),
        "last_seen": campaign.get("last_seen") or datetime.now(timezone.utc),
        "description": campaign.get("description"),
    }
    store.structured.upsert("campaigns", "id", row)
    store.graph.upsert_node("Campaign", "id", cid, name=row["name"])
    return cid


def record_malware(malware: dict[str, Any], source: str = "system") -> str:
    mid = malware.get("id") or f"mal_{uuid.uuid4().hex[:10]}"
    row = {
        "id": mid,
        "name": malware["name"],
        "aliases": malware.get("aliases", []),
        "threat_actor": malware.get("threat_actor"),
        "techniques": malware.get("techniques", []),
        "first_seen": malware.get("first_seen"),
        "last_seen": malware.get("last_seen") or datetime.now(timezone.utc),
    }
    store.structured.upsert("malware_families", "id", row)
    store.graph.upsert_node("MalwareFamily", "id", mid, name=row["name"])
    return mid


def list_actors(limit: int = 50) -> list[dict[str, Any]]:
    return store.structured.query("threat_actors", limit=limit)
