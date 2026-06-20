import logging
from typing import Dict, Any, Callable

logger = logging.getLogger(__name__)

class ShadowModePipeline:
    """
    Implements a 'Shadow Mode' testing pipeline (Phase 0 Quick Win).
    Allows running experimental detection rules alongside production without affecting actual traffic.
    """
    
    def __init__(self):
        self.shadow_alerts = []
        
    def execute_in_shadow(self, rule_name: str, rule_func: Callable, payload: Dict[str, Any]):
        """
        Executes a detection rule in shadow mode. 
        Logs the result but takes no autonomous action.
        """
        logger.info(f"[SHADOW MODE] Executing experimental rule: {rule_name}")
        
        try:
            result = rule_func(payload)
            if result.get("detected"):
                logger.warning(f"[SHADOW MODE] Rule '{rule_name}' triggered on payload. (Action Suppressed)")
                self.shadow_alerts.append({
                    "rule": rule_name,
                    "payload": payload,
                    "result": result
                })
        except Exception as e:
            logger.error(f"[SHADOW MODE] Rule '{rule_name}' crashed during execution: {e}")
            
    def get_shadow_metrics(self):
        logger.info(f"[SHADOW MODE] Total alerts caught in shadow queue: {len(self.shadow_alerts)}")
        return {"total_shadow_alerts": len(self.shadow_alerts)}
