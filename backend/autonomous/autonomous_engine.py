import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AutonomousResponseEngine:
    """
    Self-Healing Playbook Orchestrator (Phase 2 Critical Upgrade).
    Implements Tier 0 (Auto-Block), Tier 1 (Auto-Investigate), and Tier 2 (Human-in-the-Loop).
    Safety guardrails enforced via OPA policies.
    """

    @staticmethod
    def evaluate_and_respond(incident: Dict[str, Any], confidence: float, severity: str) -> str:
        """
        Evaluates an incident and executes the appropriate autonomous tier.
        """
        target_ip = incident.get("attacker_ip", "0.0.0.0")
        
        # Tier 0: Auto-Block (Immediate isolation without human approval)
        # Conditions: Confidence > 95% AND Severity == CRITICAL
        if confidence > 95.0 and severity.upper() == "CRITICAL":
            logger.warning(f"[TIER 0: AUTO-BLOCK] Executing immediate isolation for {target_ip}. Confidence: {confidence}%")
            return AutonomousResponseEngine._execute_tier_0_playbook(target_ip)
            
        # Tier 1: Auto-Investigate (Auto-run forensic playbooks, but do not block)
        # Conditions: 80% < Confidence <= 95%
        elif 80.0 < confidence <= 95.0:
            logger.info(f"[TIER 1: AUTO-INVESTIGATE] Triggering forensic collection for {target_ip}. Confidence: {confidence}%")
            return AutonomousResponseEngine._execute_tier_1_playbook(target_ip)
            
        # Tier 2: Human-in-the-Loop (Escalate to analysts)
        # Conditions: Confidence <= 80%
        else:
            logger.info(f"[TIER 2: ESCALATE] Escalating to human analysts. Confidence: {confidence}%")
            return "Escalated to analysts. No autonomous action taken."

    @staticmethod
    def _execute_tier_0_playbook(target_ip: str) -> str:
        """Executes a destructive or isolation action. Must respect OPA guardrails (mocked)."""
        # In production: Check OPA policy before execution.
        # e.g., requests.post("http://opa:8181/v1/data/edysor/kill_switch/trigger_shutdown", ...)
        # We assume Crown Jewels are protected by the policy updated in Phase 1.
        action = f"Blocked IP {target_ip} at the edge firewall."
        return action

    @staticmethod
    def _execute_tier_1_playbook(target_ip: str) -> str:
        """Executes non-destructive data collection."""
        action = f"Snapshotted VM and collected memory dump for interactions with {target_ip}."
        return action
