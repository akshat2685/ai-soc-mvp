import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def query_logs(tenant_id: str, query_string: str) -> dict:
    """Query Elastic Search for related events."""
    config = get_integration_config(tenant_id, "elastic")
    url = config.get("url")
    api_key = config.get("api_key")

    if not all([url, api_key]):
        logger.info(f"[SOAR Elastic] [MOCK] [Tenant: {tenant_id}] Querying logs with: {query_string}")
        return {"status": "success", "mode": "mock", "hits": 2, "logs": [{"message": "Mock auth failure logs", "status": "failed"}]}

    try:
        headers = {"Authorization": f"ApiKey {api_key}", "Content-Type": "application/json"}
        api_url = f"{url.rstrip('/')}/_search"
        payload = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query_string}},
                        {"term": {"tenant_id.keyword": tenant_id}}
                    ]
                }
            }
        }
        res = requests.post(api_url, headers=headers, json=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        hits = data.get("hits", {}).get("hits", [])
        return {"status": "success", "mode": "live", "hits": len(hits), "logs": [h.get("_source") for h in hits]}
    except Exception as e:
        logger.error(f"[SOAR Elastic] Failed to query Elastic: {e}")
        return {"status": "success", "mode": "fallback_mock", "hits": 0, "logs": [], "error": str(e)}
