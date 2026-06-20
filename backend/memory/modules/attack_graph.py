"""Attack graph memory module. Stores the reconstructed attack chain for every
incident — nodes, edges, mermaid visualization, and a textual summary."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from .. import store
from ..schemas import MemoryType

log = logging.getLogger(__name__)
_TABLE = "attack_graphs"
_TYPE = MemoryType.ATTACK_GRAPH.value


def record(graph: dict[str, Any], source: str = "system") -> str:
    ag_id = graph.get("id") or f"ag_{uuid.uuid4().hex[:10]}"
    row = {
        "id": ag_id,
        "incident_id": graph.get("incident_id"),
        "nodes": graph.get("nodes", []),
        "edges": graph.get("edges", []),
        "mermaid_code": graph.get("mermaid_code"),
        "summary": graph.get("summary"),
    }
    store.structured.upsert(_TABLE, "id", row)

    obj_id = store.structured.record_memory_object(
        object_id=f"{_TYPE}_{ag_id}",
        type_=_TYPE,
        ref_table=_TABLE,
        ref_id=ag_id,
        source=source,
        confidence=0.7,
        trust=0.7,
        impact=0.7,
        tags=["attack_graph"],
        search_text=graph.get("summary", ""),
    )
    return ag_id


def get_for_incident(incident_id: str) -> dict[str, Any] | None:
    rows = store.structured.query(_TABLE, "incident_id = %s", (incident_id,), limit=1)
    return rows[0] if rows else None
