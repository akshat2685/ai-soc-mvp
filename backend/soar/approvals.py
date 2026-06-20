import json
import logging
from datetime import datetime
from database import get_db
from soar.integrations import slack, teams

logger = logging.getLogger(__name__)

def request_approval(tenant_id: str, playbook_run_id: int, action_name: str, target: str, evidence: dict = None) -> int:
    """Create a pending approval record and notify channels (Slack/Teams)."""
    evidence_str = json.dumps(evidence) if evidence else None
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO soar_approvals (tenant_id, playbook_run_id, action_name, target, status, evidence, requested_at)
            VALUES (?, ?, ?, ?, 'PENDING', ?, CURRENT_TIMESTAMP)
            """,
            (tenant_id, playbook_run_id, action_name, target, evidence_str)
        )
        conn.commit()
        approval_id = cursor.lastrowid

    # Send notifications
    msg = (
        f"🚨 *EDYSOR SOAR Approval Required* 🚨\n"
        f"Tenant: `{tenant_id}`\n"
        f"Playbook Run: #{playbook_run_id}\n"
        f"Action: `{action_name}`\n"
        f"Target: `{target}`\n"
        f"Please approve or deny this action. Approval ID: `{approval_id}`"
    )
    
    slack.send_message(tenant_id, msg)
    teams.send_message(tenant_id, msg)

    # Broadcast event via websocket if running in main context
    try:
        from main import broadcast_event
        broadcast_event({
            "type": "soar_approval_needed",
            "approval": {
                "id": approval_id,
                "tenant_id": tenant_id,
                "playbook_run_id": playbook_run_id,
                "action_name": action_name,
                "target": target,
                "evidence": evidence
            }
        })
    except Exception:
        pass

    return approval_id

def resolve_approval(approval_id: int, reviewed_by: str, status: str) -> dict:
    """Resolve a pending approval (APPROVED or DENIED)."""
    if status not in ["APPROVED", "DENIED"]:
        return {"error": "Invalid resolution status"}

    with get_db() as conn:
        # Check if exists and is pending
        cur = conn.execute("SELECT * FROM soar_approvals WHERE id = ? AND status = 'PENDING'", (approval_id,))
        approval = cur.fetchone()
        if not approval:
            return {"error": "Approval request not found or already resolved"}
        
        approval = dict(approval)
        conn.execute(
            "UPDATE soar_approvals SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, reviewed_by, approval_id)
        )
        conn.commit()

    # Log to audit_log
    try:
        from response import ResponseEngine
        engine = ResponseEngine()
        engine._write_audit(
            action_type=approval["action_name"],
            response_tier=5,
            target=approval["target"],
            incident_id=approval["playbook_run_id"],
            evidence=json.loads(approval["evidence"]) if approval["evidence"] else None,
            approval_status=status,
            approved_by=reviewed_by,
            notes=f"Resolved SOAR approval via manual review"
        )
    except Exception as e:
        logger.error(f"Failed to write audit log for approval resolution: {e}")

    # Resume playbook run in background if approved
    if status == "APPROVED":
        try:
            from soar.playbooks import resume_playbook_run
            import threading
            threading.Thread(
                target=resume_playbook_run,
                args=(approval["playbook_run_id"], reviewed_by),
                daemon=True
            ).start()
        except Exception as e:
            logger.error(f"Failed to resume playbook run {approval['playbook_run_id']}: {e}")
    else:
        # If denied, mark the playbook run as FAILED
        with get_db() as conn:
            conn.execute(
                "UPDATE soar_playbook_runs SET status = 'DENIED', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (approval["playbook_run_id"],)
            )
            conn.commit()

    return {"status": "resolved", "action": status, "approval_id": approval_id}
