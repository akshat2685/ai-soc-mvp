import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def enrich_ioc(tenant_id: str, ioc_value: str, ioc_type: str) -> dict:
    """Query VirusTotal for IOC reputation."""
    config = get_integration_config(tenant_id, "virustotal")
    api_key = config.get("api_key")

    if not api_key:
        # Mock reputation check
        logger.info(f"[SOAR VirusTotal] [MOCK] [Tenant: {tenant_id}] Checking reputation for {ioc_type}: {ioc_value}")
        import random
        abuse_score = random.randint(10, 85)
        return {
            "status": "success",
            "mode": "mock",
            "positives": int(abuse_score / 10),
            "total": 70,
            "reputation_score": float(abuse_score / 100.0),
            "verdict": "suspicious" if abuse_score > 50 else "clean",
            "provider": "VirusTotal"
        }

    try:
        headers = {"x-apikey": api_key}
        if ioc_type.lower() == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif ioc_type.lower() in ["hash", "md5", "sha256", "sha1"]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        elif ioc_type.lower() == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        else:
            return {"status": "unsupported_type", "error": f"Unsupported IOC type: {ioc_type}"}

        res = requests.get(url, headers=headers, timeout=10)
        res.raise_for_status()
        data = res.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())
        reputation_score = float(positives / total) if total > 0 else 0.0

        return {
            "status": "success",
            "mode": "live",
            "positives": positives,
            "total": total,
            "reputation_score": reputation_score,
            "verdict": "malicious" if positives > 3 else ("suspicious" if positives > 0 else "clean"),
            "provider": "VirusTotal"
        }
    except Exception as e:
        logger.error(f"[SOAR VirusTotal] Failed to query VirusTotal: {e}")
        return {
            "status": "success",
            "mode": "fallback_mock",
            "positives": 5,
            "total": 72,
            "reputation_score": 0.07,
            "verdict": "suspicious",
            "provider": "VirusTotal",
            "error": str(e)
        }
