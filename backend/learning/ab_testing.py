import logging
import random
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class ABTestingRouter:
    """
    A/B Testing Framework for Shadow/Canary Deployments (Phase 4).
    Routes a percentage of traffic to an experimental 'Canary' model to compare performance
    against the stable 'Production' model without impacting autonomous response logic.
    """
    def __init__(self, canary_traffic_percentage: float = 10.0):
        self.canary_percentage = canary_traffic_percentage
        self.metrics = {
            "production": {"processed": 0, "false_positives": 0, "true_positives": 0},
            "canary": {"processed": 0, "false_positives": 0, "true_positives": 0}
        }

    def route_incident(self, incident_id: str) -> str:
        """Determines if an incident should be processed by the Canary model."""
        # Use random routing for MVP. In prod, hash the incident_id for sticky routing.
        if random.uniform(0, 100) <= self.canary_percentage:
            return "canary"
        return "production"

    def process_and_compare(self, incident: Dict[str, Any]) -> Tuple[str, str]:
        """
        Runs both models (Shadow Mode) if routed to canary, but only uses Production for response.
        Returns the verdicts of (Production, Canary)
        """
        # Mock Production Model Verdict
        prod_verdict = "MALICIOUS" if incident.get("severity") == "HIGH" else "BENIGN"
        self.metrics["production"]["processed"] += 1
        
        route = self.route_incident(incident.get("id", "unk"))
        canary_verdict = "NOT_RUN"

        if route == "canary":
            # Mock Canary Model Verdict (Let's pretend it's more aggressive)
            canary_verdict = "MALICIOUS" if incident.get("severity") in ["HIGH", "MEDIUM"] else "BENIGN"
            self.metrics["canary"]["processed"] += 1
            
            logger.info(f"[A/B TEST] Incident {incident.get('id', 'unk')} shadowed to Canary. Prod: {prod_verdict}, Canary: {canary_verdict}")
            
            # If verdicts disagree, we log it for benchmarking
            if prod_verdict != canary_verdict:
                logger.warning(f"[A/B DISAGREEMENT] Canary deviated from Production on incident {incident.get('id')}.")

        return prod_verdict, canary_verdict

    def get_benchmarks(self) -> Dict[str, Any]:
        """Returns the current A/B test results."""
        return self.metrics
