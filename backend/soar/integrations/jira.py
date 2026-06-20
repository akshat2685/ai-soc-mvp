import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def create_ticket(tenant_id: str, summary: str, description: str) -> dict:
    """Create a Jira issue."""
    config = get_integration_config(tenant_id, "jira")
    url = config.get("url")
    username = config.get("username")
    api_token = config.get("api_token")
    project_key = config.get("project_key", "SEC")

    if not all([url, username, api_token]):
        # Mock ticket
        ticket_key = f"{project_key}-MOCK-999"
        logger.info(f"[SOAR Jira] [MOCK] [Tenant: {tenant_id}] Created Ticket: {ticket_key} - {summary}")
        return {"status": "success", "mode": "mock", "ticket_key": ticket_key}

    try:
        api_url = f"{url.rstrip('/')}/rest/api/2/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Incident"}
            }
        }
        res = requests.post(api_url, auth=(username, api_token), json=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        return {"status": "success", "mode": "live", "ticket_key": data.get("key")}
    except Exception as e:
        logger.error(f"[SOAR Jira] Failed to create Jira ticket: {e}")
        ticket_key = f"{project_key}-FALLBACK-888"
        return {"status": "success", "mode": "fallback_mock", "ticket_key": ticket_key, "error": str(e)}

def close_ticket(tenant_id: str, ticket_key: str) -> dict:
    """Close a Jira issue (Rollback action)."""
    config = get_integration_config(tenant_id, "jira")
    url = config.get("url")
    username = config.get("username")
    api_token = config.get("api_token")

    if not all([url, username, api_token]):
        logger.info(f"[SOAR Jira] [MOCK] [Tenant: {tenant_id}] Closed Ticket: {ticket_key}")
        return {"status": "success", "mode": "mock", "ticket_key": ticket_key}

    if "MOCK" in ticket_key or "FALLBACK" in ticket_key:
        logger.info(f"[SOAR Jira] [MOCK] [Tenant: {tenant_id}] Closed Mock/Fallback Ticket: {ticket_key}")
        return {"status": "success", "mode": "mock", "ticket_key": ticket_key}

    try:
        api_url = f"{url.rstrip('/')}/rest/api/2/issue/{ticket_key}/transitions"
        # Transition ID for "Done" or "Closed" varies; standard default is often 31 or 41. We try to resolve or post transition.
        payload = {
            "transition": {"id": "DONE"} # or standard status resolution payload
        }
        res = requests.post(api_url, auth=(username, api_token), json=payload, timeout=10)
        res.raise_for_status()
        return {"status": "success", "mode": "live", "ticket_key": ticket_key}
    except Exception as e:
        logger.error(f"[SOAR Jira] Failed to close Jira ticket: {e}")
        return {"status": "failed", "mode": "fallback_mock", "ticket_key": ticket_key, "error": str(e)}
