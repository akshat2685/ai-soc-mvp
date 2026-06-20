import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from auth import get_user_from_token
from database import get_db
from soar.config import get_integration_config, save_integration_config
from soar.playbooks import trigger_playbook, trigger_rollback
from soar.approvals import resolve_approval

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR Engine"])

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

class ConfigSaveRequest(BaseModel):
    config_data: Dict[str, Any] = Field(..., description="Configuration parameters as key-value pairs")

class PlaybookTriggerRequest(BaseModel):
    playbook_name: str = Field(..., description="Name of the playbook to trigger")
    target: str = Field(..., description="IP, hostname, user_id or other targets of the containment")
    incident_id: Optional[int] = Field(None, description="Optional associated incident ID")

class ApprovalResolveRequest(BaseModel):
    status: str = Field(..., description="APPROVED or DENIED")

@router.get("/config/{integration_name}", response_model=Dict[str, Any])
async def get_config(integration_name: str, user: dict = Depends(require_auth)):
    """Retrieve integration configuration for the tenant."""
    tenant_id = user.get("tenant_id", "default")
    config = get_integration_config(tenant_id, integration_name)
    return {"integration_name": integration_name, "config": config}

@router.post("/config/{integration_name}")
async def save_config(integration_name: str, req: ConfigSaveRequest, user: dict = Depends(require_auth)):
    """Save/update integration configuration for the tenant."""
    tenant_id = user.get("tenant_id", "default")
    save_integration_config(tenant_id, integration_name, req.config_data)
    return {"status": "success", "message": f"Configuration for {integration_name} saved."}

from auth.rbac import require_permission, Permission

@router.post("/trigger", response_model=Dict[str, Any])
async def trigger_playbook_endpoint(
    req: PlaybookTriggerRequest, 
    user: dict = Depends(require_auth)
):
    """Manually trigger a SOAR playbook. Requires EXECUTE_PLAYBOOK permission."""
    # Enforce RBAC
    require_permission(Permission.EXECUTE_PLAYBOOK)(user)
    
    tenant_id = user.get("tenant_id", "default")
    try:
        run_id = trigger_playbook(tenant_id, req.playbook_name, req.target, req.incident_id)
        return {"status": "success", "playbook_run_id": run_id, "playbook_name": req.playbook_name}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.exception("SOAR Playbook trigger failed")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/approvals", response_model=List[Dict[str, Any]])
async def list_pending_approvals(user: dict = Depends(require_auth)):
    """Retrieve all pending approvals for the tenant."""
    tenant_id = user.get("tenant_id", "default")
    try:
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM soar_approvals WHERE tenant_id = ? AND status = 'PENDING' ORDER BY requested_at DESC",
                (tenant_id,)
            )
            approvals = [dict(r) for r in cur.fetchall()]
        return approvals
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/approvals/{approval_id}/resolve")
async def resolve_approval_endpoint(approval_id: int, req: ApprovalResolveRequest, user: dict = Depends(require_auth)):
    """Approve or Deny a pending SOAR action."""
    require_permission(Permission.APPROVE_CRITICAL_ACTION)(user)
    tenant_id = user.get("tenant_id", "default")
    # Verify that the approval belongs to this tenant
    with get_db() as conn:
        cur = conn.execute("SELECT tenant_id FROM soar_approvals WHERE id = ?", (approval_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Approval not found")
        if row[0] != tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    result = resolve_approval(approval_id, user.get("username", "analyst"), req.status)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/history", response_model=List[Dict[str, Any]])
async def get_execution_history(user: dict = Depends(require_auth)):
    """Retrieve playbook run history with action logs for the tenant."""
    tenant_id = user.get("tenant_id", "default")
    try:
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM soar_playbook_runs WHERE tenant_id = ? ORDER BY id DESC",
                (tenant_id,)
            )
            playbooks = [dict(r) for r in cur.fetchall()]
            
            for p in playbooks:
                cur_act = conn.execute(
                    "SELECT * FROM soar_action_runs WHERE playbook_run_id = ? ORDER BY id ASC",
                    (p["id"],)
                )
                p["actions"] = [dict(a) for a in cur_act.fetchall()]
                
        return playbooks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rollback/{playbook_run_id}")
async def rollback_playbook(playbook_run_id: int, user: dict = Depends(require_auth)):
    """Manually trigger rollback of a playbook run."""
    tenant_id = user.get("tenant_id", "default")
    with get_db() as conn:
        cur = conn.execute("SELECT tenant_id FROM soar_playbook_runs WHERE id = ?", (playbook_run_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Playbook run not found")
        if row[0] != tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    try:
        trigger_rollback(playbook_run_id)
        return {"status": "success", "message": f"Rollback triggered for playbook run #{playbook_run_id}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/metrics", response_model=Dict[str, Any])
async def get_soar_metrics(user: dict = Depends(require_auth)):
    """Retrieve SOAR success metrics and KPIs for the tenant."""
    tenant_id = user.get("tenant_id", "default")
    try:
        with get_db() as conn:
            # Playbook execution stats
            cur = conn.execute("SELECT COUNT(*) as total FROM soar_playbook_runs WHERE tenant_id = ?", (tenant_id,))
            total_runs = cur.fetchone()["total"]

            cur = conn.execute("SELECT COUNT(*) as compl FROM soar_playbook_runs WHERE tenant_id = ? AND status = 'COMPLETED'", (tenant_id,))
            completed_runs = cur.fetchone()["compl"]

            cur = conn.execute("SELECT COUNT(*) as failed FROM soar_playbook_runs WHERE tenant_id = ? AND status = 'FAILED'", (tenant_id,))
            failed_runs = cur.fetchone()["failed"]

            cur = conn.execute("SELECT COUNT(*) as rolled FROM soar_playbook_runs WHERE tenant_id = ? AND status = 'ROLLED_BACK'", (tenant_id,))
            rolled_back_runs = cur.fetchone()["rolled"]

            cur = conn.execute("SELECT COUNT(*) as app FROM soar_approvals WHERE tenant_id = ?", (tenant_id,))
            total_approvals = cur.fetchone()["app"]

            cur = conn.execute("SELECT COUNT(*) as app_ok FROM soar_approvals WHERE tenant_id = ? AND status = 'APPROVED'", (tenant_id,))
            approved_approvals = cur.fetchone()["app_ok"]

            # Action execution stats
            cur = conn.execute(
                """
                SELECT COUNT(*) as total_acts, SUM(attempt_count) as total_attempts
                FROM soar_action_runs
                WHERE playbook_run_id IN (SELECT id FROM soar_playbook_runs WHERE tenant_id = ?)
                """,
                (tenant_id,)
            )
            act_stats = cur.fetchone()
            total_actions = act_stats["total_acts"] or 0
            total_attempts = act_stats["total_attempts"] or 0
            retries = max(0, total_attempts - total_actions)

        success_rate = round(completed_runs / max(1, total_runs), 4)
        approval_rate = round(approved_approvals / max(1, total_approvals), 4)

        return {
            "total_playbook_runs": total_runs,
            "completed_playbook_runs": completed_runs,
            "failed_playbook_runs": failed_runs,
            "rolled_back_playbook_runs": rolled_back_runs,
            "success_rate": success_rate,
            "total_actions_run": total_actions,
            "total_retries": retries,
            "total_approvals_requested": total_approvals,
            "approved_approvals": approved_approvals,
            "approval_rate": approval_rate
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
