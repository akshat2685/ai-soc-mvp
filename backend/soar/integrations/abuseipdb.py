import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def enrich_ip(tenant_id: str, ip_address: str) -> dict:
    """Enrich IP reputation using AbuseIPDB."""
    config = get_integration_config(tenant_id, "abuseipdb")
    api_key = config.get("api_key")

    if not api_key:
        logger.info(f"[SOAR AbuseIPDB] [MOCK] [Tenant: {tenant_id}] Checking IP {ip_address}")
        import random
        score = random.randint(5, 95)
        return {
            "status": "success",
            "mode": "mock",
            "ipAddress": ip_address,
            "abuseConfidenceScore": score,
            "totalReports": int(score * 2.5),
            "isp": "Mock ISP Inc.",
            "countryCode": "US",
            "verdict": "malicious" if score > 50 else ("suspicious" if score > 20 else "clean"),
            "provider": "AbuseIPDB"
        }

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90"
        }
        res = requests.get(url, headers=headers, params=params, timeout=10)
        res.raise_for_status()
        data = res.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return {
            "status": "success",
            "mode": "live",
            "ipAddress": ip_address,
            "abuseConfidenceScore": score,
            "totalReports": data.get("totalReports", 0),
            "isp": data.get("isp", "Unknown"),
            "countryCode": data.get("countryCode", "XX"),
            "verdict": "malicious" if score > 50 else ("suspicious" if score > 20 else "clean"),
            "provider": "AbuseIPDB"
        }
    except Exception as e:
        logger.error(f"[SOAR AbuseIPDB] Failed to query AbuseIPDB: {e}")
        return {
            "status": "success",
            "mode": "fallback_mock",
            "ipAddress": ip_address,
            "abuseConfidenceScore": 15,
            "totalReports": 3,
            "isp": "Fallback ISP",
            "countryCode": "US",
            "verdict": "suspicious",
            "provider": "AbuseIPDB",
            "error": str(e)
        }
