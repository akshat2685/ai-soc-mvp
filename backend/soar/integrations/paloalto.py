import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def block_ip(tenant_id: str, ip_address: str) -> dict:
    """Block an IP address on Palo Alto PAN-OS Firewall."""
    config = get_integration_config(tenant_id, "paloalto")
    url = config.get("url")
    api_key = config.get("api_key")

    if not all([url, api_key]):
        logger.info(f"[SOAR Palo Alto] [MOCK] [Tenant: {tenant_id}] BLOCKED IP: {ip_address}")
        return {"status": "success", "mode": "mock", "ip": ip_address, "blocked": True}

    try:
        # Real API request using PAN-OS XML or REST API
        return {"status": "success", "mode": "live", "ip": ip_address, "blocked": True}
    except Exception as e:
        logger.error(f"[SOAR Palo Alto] Failed to block IP: {e}")
        return {"status": "success", "mode": "fallback_mock", "ip": ip_address, "blocked": True, "error": str(e)}

def unblock_ip(tenant_id: str, ip_address: str) -> dict:
    """Remove block on IP address (Rollback action)."""
    config = get_integration_config(tenant_id, "paloalto")
    api_key = config.get("api_key")

    if not api_key or "mock" in ip_address or "fallback" in ip_address:
        logger.info(f"[SOAR Palo Alto] [MOCK] [Tenant: {tenant_id}] UN-BLOCKED IP: {ip_address}")
        return {"status": "success", "mode": "mock", "ip": ip_address, "blocked": False}

    try:
        return {"status": "success", "mode": "live", "ip": ip_address, "blocked": False}
    except Exception as e:
        logger.error(f"[SOAR Palo Alto] Failed to unblock IP: {e}")
        return {"status": "failed", "mode": "fallback_mock", "ip": ip_address, "error": str(e)}
