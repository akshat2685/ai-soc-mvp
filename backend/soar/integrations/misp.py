import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def enrich_ioc(tenant_id: str, ioc_value: str, ioc_type: str) -> dict:
    """Check if IOC exists in MISP threat intel feed."""
    config = get_integration_config(tenant_id, "misp")
    url = config.get("url")
    api_key = config.get("api_key")

    if not all([url, api_key]):
        logger.info(f"[SOAR MISP] [MOCK] [Tenant: {tenant_id}] Checking MISP for {ioc_type}: {ioc_value}")
        return {"status": "success", "mode": "mock", "misp_matches": [], "verdict": "clean"}

    try:
        headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
        api_url = f"{url.rstrip('/')}/attributes/search"
        payload = {"value": ioc_value, "type": ioc_type}
        res = requests.post(api_url, headers=headers, json=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        matches = data.get("response", {}).get("Attribute", [])
        return {
            "status": "success",
            "mode": "live",
            "misp_matches": matches,
            "verdict": "malicious" if len(matches) > 0 else "clean",
            "provider": "MISP"
        }
    except Exception as e:
        logger.error(f"[SOAR MISP] Failed to query MISP: {e}")
        return {"status": "success", "mode": "fallback_mock", "misp_matches": [], "verdict": "clean", "error": str(e)}

def publish_ioc(tenant_id: str, ioc_value: str, ioc_type: str) -> dict:
    """Publish a new IOC to MISP."""
    config = get_integration_config(tenant_id, "misp")
    url = config.get("url")
    api_key = config.get("api_key")

    if not all([url, api_key]):
        misp_id = "mock_misp_ioc_789"
        logger.info(f"[SOAR MISP] [MOCK] [Tenant: {tenant_id}] Published IOC to MISP: {ioc_type}:{ioc_value} (ID: {misp_id})")
        return {"status": "success", "mode": "mock", "misp_id": misp_id}

    try:
        headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
        api_url = f"{url.rstrip('/')}/events/add"
        payload = {
            "Event": {
                "info": f"EDYSOR Threat Intel Export - Tenant {tenant_id}",
                "Attribute": [{"value": ioc_value, "type": ioc_type}]
            }
        }
        res = requests.post(api_url, headers=headers, json=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        misp_id = data.get("Event", {}).get("id")
        return {"status": "success", "mode": "live", "misp_id": misp_id}
    except Exception as e:
        logger.error(f"[SOAR MISP] Failed to publish to MISP: {e}")
        return {"status": "success", "mode": "fallback_mock", "misp_id": "fallback_misp_id", "error": str(e)}

def delete_ioc(tenant_id: str, misp_id: str) -> dict:
    """Delete an IOC event from MISP (Rollback action)."""
    config = get_integration_config(tenant_id, "misp")
    url = config.get("url")
    api_key = config.get("api_key")

    if not all([url, api_key]) or "mock" in misp_id or "fallback" in misp_id:
        logger.info(f"[SOAR MISP] [MOCK] [Tenant: {tenant_id}] Deleted IOC Event: {misp_id}")
        return {"status": "success", "mode": "mock", "misp_id": misp_id}

    try:
        headers = {"Authorization": api_key, "Accept": "application/json"}
        api_url = f"{url.rstrip('/')}/events/delete/{misp_id}"
        res = requests.post(api_url, headers=headers, timeout=10)
        res.raise_for_status()
        return {"status": "success", "mode": "live", "misp_id": misp_id}
    except Exception as e:
        logger.error(f"[SOAR MISP] Failed to delete from MISP: {e}")
        return {"status": "failed", "mode": "fallback_mock", "misp_id": misp_id, "error": str(e)}
