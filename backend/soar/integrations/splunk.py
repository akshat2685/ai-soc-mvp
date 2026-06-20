import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def query_events(tenant_id: str, query_string: str) -> dict:
    """Query Splunk for search jobs or events."""
    config = get_integration_config(tenant_id, "splunk")
    url = config.get("url")
    token = config.get("token")

    if not all([url, token]):
        logger.info(f"[SOAR Splunk] [MOCK] [Tenant: {tenant_id}] Splunk search: {query_string}")
        return {"status": "success", "mode": "mock", "results": [{"_raw": "Mock Splunk log line"}]}

    try:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"}
        api_url = f"{url.rstrip('/')}/services/search/jobs"
        payload = {
            "search": f"search tenant_id={tenant_id} {query_string}",
            "output_mode": "json"
        }
        res = requests.post(api_url, headers=headers, data=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        return {"status": "success", "mode": "live", "results": data.get("results", [])}
    except Exception as e:
        logger.error(f"[SOAR Splunk] Failed to query Splunk: {e}")
        return {"status": "success", "mode": "fallback_mock", "results": [], "error": str(e)}
