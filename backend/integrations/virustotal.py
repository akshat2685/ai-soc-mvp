import logging
import random
from typing import Dict, Any

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """
    Mock VirusTotal API Client for auto-enrichment (Phase 0 Quick Win).
    """
    def __init__(self, api_key: str = "VT_MOCK_KEY_123"):
        self.api_key = api_key
        
    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        logger.info(f"[VIRUSTOTAL] Querying reputation for IP: {ip_address}")
        # Mock logic based on IP address
        if ip_address.startswith("10.") or ip_address.startswith("192.168."):
            return {"malicious": 0, "suspicious": 0, "harmless": 80, "score": 0}
            
        # Simulate a random hit for public IPs
        malicious_hits = random.randint(0, 15)
        return {
            "malicious": malicious_hits,
            "suspicious": random.randint(0, 5),
            "harmless": random.randint(50, 90),
            "score": malicious_hits * 10
        }
        
    def get_file_hash_report(self, file_hash: str) -> Dict[str, Any]:
        logger.info(f"[VIRUSTOTAL] Querying report for hash: {file_hash}")
        # Simulate hit if hash starts with 'e' (evil)
        if file_hash.lower().startswith('e'):
            return {"malicious": 56, "tags": ["ransomware", "trojan"], "score": 95}
        return {"malicious": 0, "tags": [], "score": 0}
