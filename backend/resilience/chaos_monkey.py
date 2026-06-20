import logging
import random
import time
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ChaosMonkey:
    """
    Implements Chaos Engineering principles (OBJ 14).
    Randomly injects faults to ensure the SOC's circuit breakers and fallback mechanisms work.
    """
    
    @staticmethod
    def inject_latency(max_latency_ms: int = 5000):
        delay = random.randint(500, max_latency_ms) / 1000.0
        logger.warning(f"[CHAOS MONKEY] Injecting {delay}s latency into the network layer.")
        time.sleep(delay)
        
    @staticmethod
    def simulate_database_drop():
        logger.error("[CHAOS MONKEY] Simulating sudden database connection drop.")
        raise ConnectionError("Chaos Monkey injected Database Connection Failure.")
        
    @staticmethod
    def trigger_random_fault(probability: float = 0.1):
        """Randomly triggers a fault based on the probability."""
        if random.random() < probability:
            fault_type = random.choice(["latency", "db_drop"])
            if fault_type == "latency":
                ChaosMonkey.inject_latency()
            else:
                ChaosMonkey.simulate_database_drop()
