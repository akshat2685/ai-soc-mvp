"""Purple Team API Router.

Exposes endpoints for running atomic simulations, checking detection coverage,
and viewing staged Sigma rules.
"""
from __future__ import annotations

import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from auth import get_user_from_token
from database import get_db
from . import orchestrator

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/purple_team", tags=["Purple Team"])


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


class ValidationRequest(BaseModel):
    technique_id: str = Field("T1110.004", description="MITRE Technique ID (e.g. T1110.004)")
    technique_name: str = Field("Credential Stuffing", description="Name of the technique")
    target_ip: str = Field("192.168.1.50", description="IP address of the target host")
    agent_id: Optional[str] = Field(None, description="Caldera agent identifier")


@router.post("/validate", response_model=Dict[str, Any])
async def trigger_validation(req: ValidationRequest, user: dict = Depends(require_auth)):
    """Runs a full simulation-detection loop against the target IP."""
    try:
        result = orchestrator.run_purple_team_cycle(
            technique_id=req.technique_id,
            technique_name=req.technique_name,
            target_ip=req.target_ip,
            agent_id=req.agent_id
        )
        return result
    except Exception as e:
        log.exception("Purple Team validation run failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/coverage", response_model=Dict[str, Any])
async def get_coverage_score(user: dict = Depends(require_auth)):
    """Retrieves threat validation coverage score based on past simulations."""
    try:
        with get_db() as conn:
            # Count distinct technique IDs that have been validated and detected
            total_sims_cur = conn.execute("SELECT COUNT(DISTINCT name) as c FROM simulations WHERE name LIKE 'Purple Team validation:%'")
            total_sims = total_sims_cur.fetchone()['c']
            
            # Simple heuristic calculations for coverage, quality, and detection speed
            detected_cur = conn.execute("SELECT COUNT(*) as c FROM evaluations WHERE sim_id IN (SELECT sim_id FROM simulations WHERE name LIKE 'Purple Team validation:%') AND precision > 0.5")
            detected_count = detected_cur.fetchone()['c']
            
            # Average detection speed
            mttd_cur = conn.execute("SELECT AVG(mttd) as avg_mttd FROM evaluations WHERE sim_id IN (SELECT sim_id FROM simulations WHERE name LIKE 'Purple Team validation:%') AND mttd > 0.0")
            avg_mttd = mttd_cur.fetchone()['avg_mttd'] or 0.0
            
        coverage_score = round(detected_count / max(1, total_sims), 4)
        
        return {
            "total_validated_techniques": total_sims,
            "detected_techniques": detected_count,
            "coverage_score": coverage_score,
            "mean_detection_time_sec": round(avg_mttd, 2),
            "detection_quality": "High" if coverage_score > 0.8 else "Medium" if coverage_score > 0.5 else "Low"
        }
    except Exception as e:
        log.exception("Failed to query coverage score")
        raise HTTPException(status_code=500, detail=str(e))
