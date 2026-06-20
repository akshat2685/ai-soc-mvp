import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class OnlineLearningEngine:
    """
    Implements continuous learning loops (OBJ 17 & 20).
    Dynamically adjusts detection weights and thresholds based on Analyst Feedback and Purple Team failures.
    """
    
    def __init__(self):
        # Simulated weights for various detection heuristics
        self.detection_weights = {
            "credential_stuffing": 0.85,
            "prompt_injection": 0.90,
            "anomalous_login": 0.75
        }
        
    def process_analyst_feedback(self, detection_type: str, verdict: str):
        """
        Adjusts weights based on true/false positive feedback from human analysts.
        """
        current_weight = self.detection_weights.get(detection_type, 0.5)
        
        if verdict == "FALSE_POSITIVE":
            # Penalize the weight (reduce confidence)
            new_weight = max(0.1, current_weight - 0.05)
            logger.info(f"[ONLINE LEARNING] Analyst marked {detection_type} as FP. Decreasing weight: {current_weight:.2f} -> {new_weight:.2f}")
        elif verdict == "TRUE_POSITIVE":
            # Reward the weight (increase confidence)
            new_weight = min(1.0, current_weight + 0.02)
            logger.info(f"[ONLINE LEARNING] Analyst marked {detection_type} as TP. Increasing weight: {current_weight:.2f} -> {new_weight:.2f}")
        else:
            new_weight = current_weight
            
        self.detection_weights[detection_type] = new_weight
        return new_weight
        
    def process_self_play_failure(self, missed_technique: str):
        """
        When the Blue Agent misses an attack in self-play, increase sensitivity for that technique.
        """
        logger.warning(f"[ONLINE LEARNING] Blue Agent missed {missed_technique} during self-play. Triggering online parameter tuning to increase sensitivity.")
        # Simulated tuning
        return {"tuning_status": "COMPLETED", "technique": missed_technique}
