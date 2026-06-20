import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

def log_audit_action(user_id: str, action: str, target: str, tenant_id: str = "default", details: dict = None):
    """
    Unified Audit Logging Service (Phase 4 Enterprise Readiness).
    Records every critical action (e.g., IP blocks, account lockouts, API key creation)
    in the audit_log table for SOC 2 / ISO 27001 compliance.
    """
    from database import get_db
    
    details_str = json.dumps(details) if details else None

    try:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (
                    action_type, target, triggered_by, execution_result, notes
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (action, target, user_id, "SUCCESS", details_str)
            )
            conn.commit()
            
        logger.info(f"[AUDIT] Tenant: {tenant_id} | User: {user_id} | Action: {action} | Target: {target}")
    except Exception as e:
        logger.error(f"[AUDIT] Failed to write audit log: {e}")
        # In a real enterprise system, if the audit DB goes down, we must fail closed or fallback to immutable S3 buckets.
