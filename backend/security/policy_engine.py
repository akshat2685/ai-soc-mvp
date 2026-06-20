import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

# Basic OPA rules represented as cedar/rego policies in Python for compatibility
OPA_POLICIES = {
    "threat_hunter": {
        "allowed_actions": ["read_logs", "query_incidents", "map_mitre"],
        "max_risk_limit": 0.9
    },
    "knowledge": {
        "allowed_actions": ["read_intel", "query_threat_actors", "graph_retrieval"],
        "max_risk_limit": 0.8
    },
    "root_cause": {
        "allowed_actions": ["read_assets", "query_vulnerabilities", "read_cve_feed"],
        "max_risk_limit": 0.85
    },
    "soar": {
        "allowed_actions": ["read_playbooks", "simulate_containment", "execute_containment"],
        "max_risk_limit": 0.7  # SOAR actions require strict risk control
    },
    "supervisor": {
        "allowed_actions": ["route_task", "consensus_audit", "delegate_subtask"],
        "max_risk_limit": 0.95
    }
}

class OPAPolicyEngine:
    @staticmethod
    def evaluate_authorization(agent_name: str, action: str, context: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates agent permissions, tenant boundary limits, and context-aware risk scores."""
        # 1. Tenant boundary validation
        tenant_id = context.get("tenant_id", "default")
        resource_tenant = context.get("resource_tenant_id", tenant_id)
        if tenant_id != resource_tenant:
            reason = f"Tenant Boundary Breach: Agent tenant '{tenant_id}' cannot access resource owned by '{resource_tenant}'"
            logger.warning(f"[OPA Engine] {reason}")
            return False, reason

        # 2. Risk check
        risk_score = float(context.get("risk_score", 0.0))
        agent_policy = OPA_POLICIES.get(agent_name)
        if not agent_policy:
            # Fallback permissive default for other roles (planner, reporting, executive)
            return True, "Authorized (no policy constraints defined for agent role)"

        max_risk = agent_policy["max_risk_limit"]
        if risk_score > max_risk:
            reason = f"Context risk score ({risk_score}) exceeds policy limit ({max_risk}) for agent role '{agent_name}'"
            logger.warning(f"[OPA Engine] {reason}")
            return False, reason

        # 3. Action permissions check
        allowed = agent_policy["allowed_actions"]
        if action not in allowed:
            reason = f"Action '{action}' not authorized for agent role '{agent_name}'"
            logger.warning(f"[OPA Engine] {reason}")
            return False, reason

        return True, "Authorized successfully"
