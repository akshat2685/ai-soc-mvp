"""Memory Platform REST API.

Exposes the full memory platform over HTTP so the existing SOC and any AI agent
can talk to it. Runs as its own FastAPI service on port 8001 by default.

Run:
    python -m backend.memory.memory_api
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from . import access, connections, embeddings, graphrag, soc_client
from .config import get_settings
from .engines import decay, learning, quality, retrieval, scoring
from .migrations import apply as migrations_apply
from .modules import (
    agent_decisions,
    assets,
    attack_graph,
    detections,
    false_positives,
    incidents,
    investigations,
    iocs,
    lessons_learned,
    playbooks,
    threat_intel,
    user_behavior,
)
from .schemas import AgentRole, MemoryType, RecallRequest

log = logging.getLogger(__name__)
_settings = get_settings()


# Map memory type -> module that has a `record(dict)` function
_MODULE_WRITERS: dict[str, Any] = {
    MemoryType.INCIDENT.value: incidents,
    MemoryType.INVESTIGATION.value: investigations,
    MemoryType.THREAT_INTEL.value: threat_intel,          # actor/campaign/malware via the same module
    MemoryType.IOC.value: iocs,
    MemoryType.USER_BEHAVIOR.value: user_behavior,
    MemoryType.ASSET.value: assets,
    MemoryType.DETECTION.value: detections,
    MemoryType.PLAYBOOK.value: playbooks,
    MemoryType.FALSE_POSITIVE.value: false_positives,
    MemoryType.LESSON_LEARNED.value: lessons_learned,
    MemoryType.ATTACK_GRAPH.value: attack_graph,
    MemoryType.AGENT_DECISION.value: agent_decisions,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Memory Platform starting up...")
    yield
    connections.close_all()
    soc_client.close()


app = FastAPI(title="AI SOC Memory Platform API", version="1.0.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class IngestRequest(BaseModel):
    type: MemoryType
    payload: dict[str, Any]
    source: str = "api"


class LearnRequest(BaseModel):
    incident_id: str
    verdict: str
    iocs_seen: list[dict[str, Any]] | None = None
    detection_id: str | None = None
    playbook_id: str | None = None
    playbook_success: bool | None = None
    playbook_duration_sec: float | None = None
    analyst_feedback: str = ""


class GraphRAGRequest(BaseModel):
    query: str
    top_k: int = 5
    expand_hops: int = 2


class BlastRadiusRequest(BaseModel):
    entity_label: str
    key_field: str = "value"
    key_value: str
    max_hops: int = 3


# ---------------------------------------------------------------------------
# Health & diagnostics
# ---------------------------------------------------------------------------
@app.get("/memory/health")
def health():
    from .store import graph as graph_store, semantic

    return {
        "backends": connections.health(),
        "embeddings_backend": embeddings.backend_name(),
        "embedding_dim": _settings.embeddings.dim,
        "soc_reachable": soc_client.is_reachable(),
        "neo4j_node_counts": _safe(graph_store.stats),
    }


def _safe(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
@app.post("/memory/ingest/{mem_type}")
def ingest(mem_type: MemoryType, req: IngestRequest, role: str = Query("investigation", description="agent role")):
    """Store a memory object. Enforces RBAC."""
    if mem_type != req.type:
        raise HTTPException(400, f"path type {mem_type} != body type {req.type}")
    principal = access.Principal.for_role(role)
    try:
        access.authorize(principal, access.Permission.WRITE, mem_type.value)
    except PermissionError as e:
        raise HTTPException(403, str(e))

    module = _MODULE_WRITERS.get(mem_type.value)
    if not module:
        raise HTTPException(400, f"no writer registered for {mem_type}")
    try:
        new_id = module.record({**req.payload, "source": req.source}, source=req.source)
        return {"status": "stored", "type": mem_type.value, "id": new_id}
    except Exception as e:
        log.exception("ingest failed")
        raise HTTPException(500, f"ingest failed: {e}")


# ---------------------------------------------------------------------------
# Search / recall
# ---------------------------------------------------------------------------
@app.post("/memory/recall")
def recall_endpoint(req: RecallRequest, role: str = Query("triage")):
    """Run the 8-step retrieval pipeline for a new alert."""
    try:
        return retrieval.recall(req).model_dump()
    except Exception as e:
        log.exception("recall failed")
        raise HTTPException(500, f"recall failed: {e}")


@app.get("/memory/search")
def search(
    collection: str = Query(..., description="Qdrant collection short name"),
    q: str = Query(..., description="query text"),
    top_k: int = Query(5, ge=1, le=50),
):
    """Semantic search a single Qdrant collection."""
    from .store import semantic

    return semantic.search(collection=collection, query_text=q, top_k=top_k)


@app.post("/memory/graphrag")
def graphrag_endpoint(req: GraphRAGRequest):
    """Fused vector + graph + structured retrieval (enriched investigations)."""
    try:
        return graphrag.graphrag(req.query, top_k=req.top_k, expand_hops=req.expand_hops)
    except Exception as e:
        log.exception("graphrag failed")
        raise HTTPException(500, str(e))


@app.post("/memory/graph/blast-radius")
def blast_radius_endpoint(req: BlastRadiusRequest):
    from .store import graph as graph_store

    try:
        return {"edges": graph_store.blast_radius(req.entity_label, req.key_field, req.key_value, req.max_hops)}
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Playbook recommendation
# ---------------------------------------------------------------------------
@app.get("/memory/playbooks/recommend")
def recommend_playbook(attack_type: str = Query(...)):
    recs = playbooks.recommend(attack_type, top_k=3)
    return {"attack_type": attack_type, "recommended": recs}


# ---------------------------------------------------------------------------
# Continuous learning
# ---------------------------------------------------------------------------
@app.post("/memory/learn")
def learn_endpoint(req: LearnRequest, role: str = Query("investigation")):
    principal = access.Principal.for_role(role)
    try:
        access.authorize(principal, access.Permission.LEARN)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    try:
        return learning.record_outcome(**req.model_dump())
    except Exception as e:
        log.exception("learn failed")
        raise HTTPException(500, str(e))


@app.post("/memory/quality/decay")
def run_decay(batch: int = Query(500, ge=1, le=10000)):
    return decay.apply_decay(batch)


@app.post("/memory/quality/cleanup")
def run_cleanup(threshold: float = Query(0.25), older_than_days: int = Query(365)):
    return quality.cleanup(threshold, older_than_days)


@app.post("/memory/scoring/recompute")
def recompute(batch: int = Query(500)):
    return {"recomputed": scoring.recompute_all(batch)}


# ---------------------------------------------------------------------------
# Migrations (ops convenience)
# ---------------------------------------------------------------------------
@app.post("/memory/migrations/apply")
def apply_migrations(reset: bool = Query(False, description="DESTRUCTIVE: drops & recreates")):
    return migrations_apply.apply_all(reset=reset)


@app.get("/memory/rbac/roles")
def rbac_roles():
    return access.describe_roles()


@app.get("/memory/soc/status")
def soc_status():
    return {
        "reachable": soc_client.is_reachable(),
        "stats": soc_client.get_stats(),
        "soc_api_url": _settings.soc_api_url,
    }


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    uvicorn.run(
        "backend.memory.memory_api:app",
        host=_settings.api_host,
        port=_settings.api_port,
        reload=False,
    )
