import logging
import requests
from soar.config import get_integration_config

logger = logging.getLogger(__name__)

def send_message(tenant_id: str, text: str) -> dict:
    """Send message to a Teams channel using webhook."""
    config = get_integration_config(tenant_id, "teams")
    webhook_url = config.get("webhook_url")

    if not webhook_url:
        logger.info(f"[SOAR Teams] [MOCK] [Tenant: {tenant_id}] Teams Notification: {text}")
        return {"status": "success", "mode": "mock", "message": "Teams message logged to console (no webhook_url)"}

    try:
        response = requests.post(webhook_url, json={"text": text}, timeout=10)
        response.raise_for_status()
        return {"status": "success", "mode": "live"}
    except Exception as e:
        logger.error(f"[SOAR Teams] Failed to send Teams message: {e}")
        return {"status": "failed", "error": str(e), "mode": "fallback_mock", "message": text}
