import logging
import uuid
import yaml
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SigmaGenerator:
    """
    Auto-generates Sigma rules from new IOCs (Phase 1 Quick Win).
    """

    @staticmethod
    def generate_ip_rule(ip_address: str, source: str) -> str:
        """Generates a Sigma YAML rule for a malicious IP address."""
        rule_id = str(uuid.uuid4())
        rule = {
            "title": f"Auto-Generated IP Block ({source})",
            "id": rule_id,
            "status": "experimental",
            "description": f"Detects communication with known malicious IP from {source}.",
            "logsource": {
                "category": "firewall"
            },
            "detection": {
                "selection": {
                    "DestinationIp": ip_address
                },
                "condition": "selection"
            },
            "falsepositives": ["Unknown"],
            "level": "high",
            "tags": ["attack.command_and_control"]
        }
        
        yaml_output = yaml.dump(rule, default_flow_style=False, sort_keys=False)
        logger.info(f"[SIGMA GENERATOR] Generated new rule {rule_id} for IP {ip_address}")
        return yaml_output

    @staticmethod
    def save_rule_to_disk(yaml_content: str, filepath: str):
        with open(filepath, 'w') as f:
            f.write(yaml_content)
        logger.info(f"[SIGMA GENERATOR] Rule saved to {filepath}")
