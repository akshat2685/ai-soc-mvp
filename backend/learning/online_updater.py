import logging
from datetime import datetime, timedelta
from typing import Dict, Any

logger = logging.getLogger(__name__)

class OnlineUpdater:
    """
    Real-Time Online Learning Loop (Phase 4).
    Adjusts the confidence weights of detection models and rules dynamically based on analyst feedback and age.
    """

    def __init__(self):
        # Mock database of Sigma rules and their current confidence weights (0.0 to 1.0)
        self.rules_db = {
            "rule_sqli_01": {"weight": 0.95, "last_fired": datetime.now() - timedelta(days=5), "approvals": 10, "overrides": 1},
            "rule_stale_bot": {"weight": 0.80, "last_fired": datetime.now() - timedelta(days=40), "approvals": 5, "overrides": 0},
            "rule_noisy_login": {"weight": 0.60, "last_fired": datetime.now() - timedelta(hours=2), "approvals": 2, "overrides": 15}
        }

    def process_analyst_feedback(self, rule_id: str, is_false_positive: bool):
        """Adjusts rule weights in real-time based on analyst overrides (WebSocket ingest)."""
        if rule_id not in self.rules_db:
            return

        rule = self.rules_db[rule_id]
        if is_false_positive:
            rule["overrides"] += 1
            rule["weight"] = max(0.1, rule["weight"] - 0.05) # Penalize weight
            logger.info(f"[ONLINE LEARNING] Analyst marked FP for {rule_id}. Weight reduced to {rule['weight']:.2f}")
        else:
            rule["approvals"] += 1
            rule["weight"] = min(1.0, rule["weight"] + 0.02) # Reward weight
            logger.info(f"[ONLINE LEARNING] Analyst confirmed TP for {rule_id}. Weight increased to {rule['weight']:.2f}")

    def apply_confidence_decay(self):
        """Gradually reduces confidence in stale rules that haven't fired in >30 days."""
        now = datetime.now()
        decayed_count = 0
        
        for rule_id, data in self.rules_db.items():
            days_since_fired = (now - data["last_fired"]).days
            if days_since_fired > 30:
                # Apply exponential decay: e.g., lose 10% of weight for every month of inactivity
                decay_factor = 0.90 ** (days_since_fired / 30.0)
                old_weight = data["weight"]
                new_weight = max(0.1, old_weight * decay_factor)
                
                if old_weight != new_weight:
                    data["weight"] = new_weight
                    decayed_count += 1
                    logger.warning(f"[CONFIDENCE DECAY] {rule_id} inactive for {days_since_fired} days. Weight decayed: {old_weight:.2f} -> {new_weight:.2f}")

        return decayed_count
