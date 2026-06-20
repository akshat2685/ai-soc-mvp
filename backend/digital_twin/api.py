"""Digital Twin API router.

Exposes REST APIs for running attack simulations, calculating blast radius,
finding shortest attack paths, and retrieving network topology.
"""
from __future__ import annotations

import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from auth import get_user_from_token
from . import engine, simulation

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/digital_twin", tags=["Digital Twin"])


def require_auth(request: Request) -> dict:
    """Dependency that extracts and verifies user from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = auth_header[7:]
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


# ---------------------------------------------------------------------------
# API schemas
# ---------------------------------------------------------------------------
class SimulationRequest(BaseModel):
    start_node_id: str = Field(..., description="ID, IP, or name of the starting compromised node")
    attack_type: str = Field("LATERAL_MOVEMENT", description="RANSOMWARE, CREDENTIAL_THEFT, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT")
    risk_factor: float = Field(0.5, ge=0.0, le=1.0, description="Propagation risk factor")


class BlastRadiusResponse(BaseModel):
    edges: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@router.post("/simulate", response_model=Dict[str, Any])
async def simulate_attack_endpoint(req: SimulationRequest, user: dict = Depends(require_auth)):
    """Run an attack simulation on the digital twin graph."""
    try:
        result = simulation.simulate_attack(
            start_node_id=req.start_node_id,
            attack_type=req.attack_type,
            risk_factor=req.risk_factor
        )
        if result.get("status") == "failed":
            raise HTTPException(status_code=400, detail=result.get("error"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Simulation endpoint failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blast-radius", response_model=Dict[str, Any])
async def blast_radius_endpoint(
    node_id: str = Query(..., description="The node ID or IP"),
    node_label: str = Query("Host", description="Neo4j label of the starting node (Host, User, IP)"),
    max_hops: int = Query(3, ge=1, le=5, description="Max hops to traverse"),
    user: dict = Depends(require_auth)
):
    """Retrieve everything reachable from a node to measure blast radius."""
    try:
        edges = engine.calculate_blast_radius(node_label, node_id, max_hops)
        return {"node_id": node_id, "node_label": node_label, "max_hops": max_hops, "edges": edges}
    except Exception as e:
        log.exception("Blast radius endpoint failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-paths", response_model=Dict[str, Any])
async def find_attack_paths_endpoint(
    from_id: str = Query(..., description="Source node ID/IP"),
    to_id: str = Query(..., description="Target node ID/IP"),
    user: dict = Depends(require_auth)
):
    """Find the shortest attack path between source and target nodes."""
    try:
        path = engine.find_attack_paths(from_id, to_id)
        return {"from_id": from_id, "to_id": to_id, "path": path}
    except Exception as e:
        log.exception("Attack paths endpoint failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exposure", response_model=Dict[str, Any])
async def critical_exposure_endpoint(user: dict = Depends(require_auth)):
    """Calculate pathways exposing critical assets to internet-facing nodes."""
    try:
        exposure = engine.calculate_critical_asset_exposure()
        return {"exposure_paths": exposure}
    except Exception as e:
        log.exception("Critical exposure endpoint failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/topology", response_model=engine.NetworkTopology)
async def get_topology_endpoint(user: dict = Depends(require_auth)):
    """Retrieve full network topology for visual representation."""
    try:
        return engine.get_network_topology()
    except Exception as e:
        log.exception("Topology endpoint failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/cleanup", response_model=Dict[str, Any])
async def cleanup_endpoint(
    sim_id: Optional[str] = Query(None, description="Simulation ID to clear. If omitted, clears all simulations."),
    user: dict = Depends(require_auth)
):
    """Clear simulated attack relationship data from Neo4j."""
    try:
        return simulation.cleanup_simulations(sim_id)
    except Exception as e:
        log.exception("Cleanup endpoint failed")
        raise HTTPException(status_code=500, detail=str(e))
