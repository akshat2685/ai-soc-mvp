import logging
import json
import redis
from typing import Dict, Any, List
from .sigma_generator import SigmaGenerator

logger = logging.getLogger(__name__)

class ThreatFusionEngine:
    """
    Multi-Source Threat Intelligence Aggregation Layer (Phase 2 Critical Upgrade).
    Pulls IOCs from VT, MISP, OTX, and Abuse.ch.
    Calculates confidence-weighted scoring and caches in Redis (24h TTL).
    """
    def __init__(self):
        try:
            self.redis = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        except Exception:
            self.redis = None

    def fetch_misp_reputation(self, ioc: str) -> float:
        """Mock fetching MISP reputation (0.0 to 1.0)."""
        # In production: requests.post('https://misp.internal/attributes/restSearch', headers=...)
        if ioc == "185.15.5.5": return 0.95
        return 0.1

    def fetch_otx_pulses(self, ioc: str) -> float:
        """Mock fetching AlienVault OTX pulse count reputation."""
        if ioc == "185.15.5.5": return 0.88
        return 0.0

    def fetch_abuse_ch(self, ioc: str) -> float:
        """Mock fetching Abuse.ch ThreatFox/FeodoTracker."""
        if ioc == "185.15.5.5": return 1.0
        return 0.0

    def fetch_vt_score(self, ioc: str) -> float:
        """Mock fetching VirusTotal malicious votes ratio."""
        if ioc == "185.15.5.5": return 0.92
        return 0.0

    def calculate_fused_confidence(self, ioc: str) -> Dict[str, Any]:
        """Calculates a fused confidence score from multiple STIX/TAXII compatible sources."""
        
        # Check cache first
        if self.redis:
            try:
                cached = self.redis.get(f"threat_fusion:{ioc}")
                if cached:
                    logger.info(f"[THREAT FUSION] Cache hit for {ioc}")
                    return json.loads(cached)
            except Exception:
                pass

        # Fetch from all sources
        vt = self.fetch_vt_score(ioc)
        misp = self.fetch_misp_reputation(ioc)
        otx = self.fetch_otx_pulses(ioc)
        abuse = self.fetch_abuse_ch(ioc)

        # Weighted scoring (e.g., Abuse.ch is highly trusted for C2s, VT for general malware)
        fused_score = (vt * 0.4) + (misp * 0.3) + (otx * 0.1) + (abuse * 0.2)
        
        result = {
            "ioc": ioc,
            "fused_confidence": round(fused_score * 100, 2),
            "sources": {
                "virustotal": vt,
                "misp": misp,
                "alienvault_otx": otx,
                "abuse_ch": abuse
            },
            "is_malicious": fused_score > 0.7
        }

        # Auto-generate Sigma rule if highly malicious and not cached
        if result["is_malicious"]:
            yaml_rule = SigmaGenerator.generate_ip_rule(ioc, source="ThreatFusionEngine")
            # In production: push to clickhouse/kafka
            
        # Cache for 24 hours
        if self.redis:
            try:
                self.redis.setex(f"threat_fusion:{ioc}", 86400, json.dumps(result))
            except Exception:
                pass

        logger.info(f"[THREAT FUSION] Fused score for {ioc}: {result['fused_confidence']}%")
        return result
