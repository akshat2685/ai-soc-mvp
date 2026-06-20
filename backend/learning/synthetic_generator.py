import logging
import random
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

try:
    from faker import Faker
except ImportError:
    # Fallback if faker is not installed during standard SOC operations
    Faker = None

logger = logging.getLogger(__name__)

class SyntheticAttackGenerator:
    """
    Generates massive synthetic attack telemetry for training the ML models.
    Provides safe, isolated data for IsolationForest and Gemini Fine-Tuning.
    """
    
    @staticmethod
    def generate_training_dataset(count: int = 1000) -> List[Dict[str, Any]]:
        if not Faker:
            logger.error("[SYNTHETIC GEN] 'faker' library is required for massive generation. Run: pip install faker")
            return []
            
        fake = Faker()
        logger.info(f"[SYNTHETIC GEN] Generating {count} massive realistic attacks for ML Training...")
        
        attacks = []
        for _ in range(count):
            attack_type = random.choice([
                "brute_force", "phishing", "lateral_movement", "sql_injection"
            ])
            
            base_log = {
                "timestamp": fake.iso8601(),
                "source_ip": fake.ipv4(),
                "target_ip": fake.ipv4(),
                "user_id": fake.user_name(),
                "user_agent": fake.user_agent(),
                "attack_type": attack_type
            }
            
            if attack_type == "brute_force":
                base_log.update({
                    "event_type": "ssh_failed",
                    "endpoint": "/login",
                    "method": "POST",
                    "status": 401,
                    "mitre_ttps": ["T1110"],
                    "failed_attempts": random.randint(10, 500)
                })
            elif attack_type == "phishing":
                base_log.update({
                    "event_type": "email_received",
                    "subject": fake.sentence(),
                    "body": fake.paragraph(),
                    "url": f"http://{fake.domain_name()}/login",
                    "mitre_ttps": ["T1566.002"]
                })
            elif attack_type == "lateral_movement":
                base_log.update({
                    "event_type": "smb_connect",
                    "endpoint": "\\\\server\\share",
                    "method": "SMB",
                    "status": 200,
                    "mitre_ttps": ["T1021.002"],
                    "geo_distance_km": 0
                })
            else:
                payloads = ["' OR 1=1--", "'; DROP TABLE users--", "admin' #"]
                base_log.update({
                    "event_type": "SQL_INJECTION",
                    "endpoint": "/api/v1/users/search",
                    "method": "GET",
                    "payload": random.choice(payloads),
                    "mitre_ttps": ["T1190"]
                })
                
            attacks.append(base_log)
            
        return attacks
