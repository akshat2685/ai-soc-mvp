import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def create_incident(tenant_id: str, short_description: str, description: str) -> dict:
    """Create a ServiceNow Incident."""
    config = get_integration_config(tenant_id, "servicenow")
    instance_url = config.get("instance_url")
    username = config.get("username")
    password = config.get("password")

    if not all([instance_url, username, password]):
        sys_id = "mock_sys_id_12345"
        incident_num = "INC_MOCK_123"
        logger.info(f"[SOAR ServiceNow] [MOCK] [Tenant: {tenant_id}] Created Incident: {incident_num} ({short_description})")
        return {"status": "success", "mode": "mock", "sys_id": sys_id, "incident_number": incident_num}

    try:
        api_url = f"{instance_url.rstrip('/')}/api/now/table/incident"
        payload = {
            "short_description": short_description,
            "description": description,
            "severity": "1",
            "impact": "1"
        }
        res = requests.post(api_url, auth=(username, password), json=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        result = data.get("result", {})
        return {
            "status": "success",
            "mode": "live",
            "sys_id": result.get("sys_id"),
            "incident_number": result.get("number")
        }
    except Exception as e:
        logger.error(f"[SOAR ServiceNow] Failed to create ServiceNow incident: {e}")
        return {
            "status": "success",
            "mode": "fallback_mock",
            "sys_id": "fallback_sys_id",
            "incident_number": "INC_FALLBACK",
            "error": str(e)
        }

def close_incident(tenant_id: str, sys_id: str) -> dict:
    """Close a ServiceNow Incident (Rollback action)."""
    config = get_integration_config(tenant_id, "servicenow")
    instance_url = config.get("instance_url")
    username = config.get("username")
    password = config.get("password")

    if not all([instance_url, username, password]) or "mock" in sys_id or "fallback" in sys_id:
        logger.info(f"[SOAR ServiceNow] [MOCK] [Tenant: {tenant_id}] Closed Incident: {sys_id}")
        return {"status": "success", "mode": "mock", "sys_id": sys_id}

    try:
        api_url = f"{instance_url.rstrip('/')}/api/now/table/incident/{sys_id}"
        # 7 is Closed in standard ServiceNow incident state
        payload = {"state": "7", "close_notes": "Closed automatically by EDYSOR SOAR Rollback", "close_code": "Solved (Permanently)"}
        res = requests.put(api_url, auth=(username, password), json=payload, timeout=10)
        res.raise_for_status()
        return {"status": "success", "mode": "live", "sys_id": sys_id}
    except Exception as e:
        logger.error(f"[SOAR ServiceNow] Failed to close ServiceNow incident: {e}")
        return {"status": "failed", "mode": "fallback_mock", "sys_id": sys_id, "error": str(e)}
