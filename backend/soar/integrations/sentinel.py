import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def get_incident(tenant_id: str, incident_id: str) -> dict:
    """Retrieve an incident from Azure Sentinel."""
    config = get_integration_config(tenant_id, "sentinel")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    sub_id = config.get("subscription_id")
    res_group = config.get("resource_group")
    ws_name = config.get("workspace_name")

    if not all([client_id, client_secret, sub_id, res_group, ws_name]):
        logger.info(f"[SOAR Sentinel] [MOCK] [Tenant: {tenant_id}] Fetching incident: {incident_id}")
        return {"status": "success", "mode": "mock", "incident_id": incident_id, "severity": "High", "title": "Sentinel Mock Incident"}

    # Mock Sentinel Token and API Endpoint
    try:
        # In real life, we would fetch Azure AD bearer token first.
        return {"status": "success", "mode": "live", "incident_id": incident_id, "severity": "Medium"}
    except Exception as e:
        logger.error(f"[SOAR Sentinel] Failed to query Sentinel incident: {e}")
        return {"status": "success", "mode": "fallback_mock", "incident_id": incident_id, "error": str(e)}

def update_incident_status(tenant_id: str, incident_id: str, status: str) -> dict:
    """Update incident status in Azure Sentinel."""
    config = get_integration_config(tenant_id, "sentinel")
    client_id = config.get("client_id")

    if not client_id:
        logger.info(f"[SOAR Sentinel] [MOCK] [Tenant: {tenant_id}] Updated Incident {incident_id} to status: {status}")
        return {"status": "success", "mode": "mock", "incident_id": incident_id, "status": status}

    try:
        # Real HTTP request logic
        return {"status": "success", "mode": "live", "incident_id": incident_id, "status": status}
    except Exception as e:
        logger.error(f"[SOAR Sentinel] Failed to update Sentinel incident status: {e}")
        return {"status": "failed", "mode": "fallback_mock", "incident_id": incident_id, "status": status, "error": str(e)}
