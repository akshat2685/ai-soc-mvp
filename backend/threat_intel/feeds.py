import httpx
import logging
from typing import Dict, Any, List
from config import settings

logger = logging.getLogger(__name__)

class ThreatIntelFeeds:
    """
    Connectors to dynamic Threat Intelligence feeds.
    Enriches IOCs (IPs, hashes) with reputation data from open sources.
    """
    
    def __init__(self):
        # We will use httpx for async HTTP requests
        self.client = httpx.AsyncClient(timeout=5.0)

    async def check_abuse_ch(self, ip_address: str) -> Dict[str, Any]:
        """Check IP against Abuse.ch ThreatFox API"""
        try:
            # ThreatFox requires POST with JSON payload
            payload = {"query": "search_ioc", "search_term": ip_address}
            response = await self.client.post("https://threatfox-api.abuse.ch/api/v1/", json=payload)
            response.raise_for_status()
            
            data = response.json()
            if data.get("query_status") == "ok":
                return {
                    "source": "Abuse.ch ThreatFox",
                    "malicious": True,
                    "confidence": 90, # Typically high confidence if present here
                    "details": data.get("data", [])[0] # Grab first hit
                }
            return {"source": "Abuse.ch ThreatFox", "malicious": False}
        except Exception as e:
            logger.error(f"Abuse.ch check failed for {ip_address}: {e}")
            return {"source": "Abuse.ch ThreatFox", "error": str(e)}

    async def check_alienvault_otx(self, ioc: str, ioc_type: str = "IPv4") -> Dict[str, Any]:
        """Check IOC against AlienVault OTX (Open Threat Exchange)"""
        # Note: OTX usually requires an API key in the 'X-OTX-API-KEY' header for full access
        # But some basic lookups are possible, or we inject it if available.
        headers = {}
        # if settings.OTX_API_KEY:
        #     headers["X-OTX-API-KEY"] = settings.OTX_API_KEY
            
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                return {
                    "source": "AlienVault OTX",
                    "malicious": pulse_count > 0,
                    "confidence": min(100, pulse_count * 10), # Heuristic: more pulses = higher confidence
                    "details": {"pulses": pulse_count}
                }
            elif response.status_code == 404:
                return {"source": "AlienVault OTX", "malicious": False}
            else:
                response.raise_for_status()
                
        except Exception as e:
            logger.error(f"AlienVault OTX check failed for {ioc}: {e}")
            return {"source": "AlienVault OTX", "error": str(e)}

    async def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Aggregate intelligence from multiple feeds for a single IP."""
        import asyncio
        
        # Run lookups concurrently
        abuse_ch_task = self.check_abuse_ch(ip_address)
        otx_task = self.check_alienvault_otx(ip_address, "IPv4")
        
        results = await asyncio.gather(abuse_ch_task, otx_task, return_exceptions=True)
        
        aggregated = {
            "ip": ip_address,
            "malicious": False,
            "max_confidence": 0,
            "feeds": []
        }
        
        for result in results:
            if isinstance(result, Exception):
                continue
            if isinstance(result, dict):
                aggregated["feeds"].append(result)
                if result.get("malicious"):
                    aggregated["malicious"] = True
                    conf = result.get("confidence", 0)
                    if conf > aggregated["max_confidence"]:
                        aggregated["max_confidence"] = conf
                        
        return aggregated

# Global instance for easy importing
threat_feeds = ThreatIntelFeeds()
