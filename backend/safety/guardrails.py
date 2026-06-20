import logging
import re
from typing import Dict, Any, Tuple
from database import get_db

logger = logging.getLogger(__name__)

# Strict safety constraints
SENSITIVE_IPS = [
    r"^127\..*",            # Loopback
    r"^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", # Private network Class A
    r"^192\.168\..*",       # Private network Class C
    r"^169\.254\..*",       # Link-local / Cloud metadata endpoints
    r"^8\.8\.8\.8$",        # Google DNS (Core network)
    r"^1\.1\.1\.1$"         # Cloudflare DNS
]

SENSITIVE_HOSTNAMES = [
    r".*dc.*",              # Domain Controllers
    r".*dns.*",             # DNS Servers
    r".*auth.*",            # Auth servers
    r"gateway",             # Gateways
    r"router"
]

def check_action_safety(action_type: str, target: str, tenant_id: str = "default") -> Tuple[bool, str]:
    """
    Check if a SOAR containment action violates safety guardrails.
    Returns (is_safe, reason).
    """
    # 1. Permanent blocks and isolations must not target critical infrastructure
    if action_type in ["BLOCK_IP", "block_ip", "TEMP_BLOCK", "PERM_BLOCK"]:
        for pattern in SENSITIVE_IPS:
            if re.match(pattern, target):
                reason = f"Action blocked: IP {target} belongs to restricted internal or core DNS subnet."
                _log_guardrail_violation(action_type, target, reason, tenant_id)
                return False, reason

    if action_type in ["SNAPSHOT_VM", "isolate_host", "isolate_machine", "ISOLATE_HOST"]:
        for pattern in SENSITIVE_HOSTNAMES:
            if re.match(pattern, target.lower()):
                reason = f"Action blocked: Hostname '{target}' identified as critical infrastructure."
                _log_guardrail_violation(action_type, target, reason, tenant_id)
                return False, reason

    # 2. Account locks must not target built-in domain admins autonomously
    if action_type in ["DISABLE_ACCOUNT", "lock_account", "lock_user"]:
        if target.lower() in ["administrator", "admin", "system", "root"]:
            reason = f"Action blocked: Target '{target}' is a reserved root/administrator credential."
            _log_guardrail_violation(action_type, target, reason, tenant_id)
            return False, reason

    return True, "Action cleared by safety guardrails."

def _log_guardrail_violation(action_type: str, target: str, reason: str, tenant_id: str):
    """Log blocked actions to the audit log."""
    logger.warning(f"[Guardrails] Blocked unsafe action: {action_type} -> {target}. Reason: {reason}")
    try:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (action_type, target, triggered_by, approval_status, execution_result, notes)
                VALUES (?, ?, 'GUARDRAIL', 'BLOCKED', 'FAILED', ?)
                """,
                (action_type, target, f"Guardrail Interception: {reason}")
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log guardrail violation: {e}")

def get_action_explainability_trace(action_id: int) -> dict:
    """Retrieve audit details explaining an action decision."""
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM audit_log WHERE id = ?", (action_id,))
        row = cur.fetchone()
        if not row:
            return {"error": "Audit entry not found"}
        
        audit = dict(row)
        # Construct audit explanation trace
        trace = {
            "action_id": audit["id"],
            "timestamp": audit["timestamp"],
            "action": audit["action_type"],
            "target": audit["target"],
            "triggered_by": audit["triggered_by"],
            "result": audit["execution_result"],
            "explanation": audit["notes"] or "No trace details available.",
            "auditable": True,
            "decision_flow": [
                "1. Event correlation triggered response playbook.",
                f"2. Safety guardrails check executed for target '{audit['target']}'.",
                f"3. Decision committed with execution_result='{audit['execution_result']}'."
            ]
        }
        return trace
