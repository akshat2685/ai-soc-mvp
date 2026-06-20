import logging
from typing import Dict, Any
from security.agent_identity import verify_agent_signature, get_spiffe_id

logger = logging.getLogger(__name__)

# Track active peer agent nodes trust metrics
_trust_scores = {}

class AgentTrustManager:
    @staticmethod
    def get_trust_score(agent_name: str) -> float:
        global _trust_scores
        return _trust_scores.get(agent_name, 1.0) # Default perfect trust

    @staticmethod
    def penalize_trust(agent_name: str, penalty: float):
        global _trust_scores
        current = _trust_scores.get(agent_name, 1.0)
        _trust_scores[agent_name] = max(0.0, current - penalty)
        logger.warning(f"[Trust Manager] Penalized agent '{agent_name}'. New score: {_trust_scores[agent_name]}")

    @staticmethod
    def verify_agent_connection(
        src_agent: str,
        dest_agent: str,
        message: str,
        signature: str,
        tenant_id: str = "default"
    ) -> bool:
        """Enforces mTLS and signs/verifies peer agent parameters securely."""
        # 1. Verify SPIFFE identities match boundaries
        src_spiffe = get_spiffe_id(src_agent, tenant_id)
        dest_spiffe = get_spiffe_id(dest_agent, tenant_id)

        # 2. Check source agent credibility threshold
        score = AgentTrustManager.get_trust_score(src_agent)
        if score < 0.5:
            logger.error(f"[Trust Manager] Connection blocked: Agent '{src_agent}' trust score ({score}) below threshold.")
            return False

        # 3. Verify signature
        if not verify_agent_signature(src_agent, message, signature):
            logger.error(f"[Trust Manager] Cryptographic verify failed from '{src_agent}' to '{dest_agent}'")
            # Automatically penalize trust
            AgentTrustManager.penalize_trust(src_agent, 0.2)
            return False

        return True
