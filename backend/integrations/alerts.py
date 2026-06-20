import logging
import time
import requests

logger = logging.getLogger(__name__)

# Mock Webhook URLs for testing
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/mock/webhook"
TEAMS_WEBHOOK_URL = "https://mock.webhook.office.com/webhookb2"

class AlertManager:
    """Handles external alerting for SOC SLAs (Phase 1 Quick Win)."""

    @staticmethod
    def send_slack_alert(message: str):
        payload = {"text": f"🚨 *EDYSOR-X SLA ALERT* 🚨\n{message}"}
        try:
            # Mocking the POST request
            logger.warning(f"[SLACK ALERT] {payload['text']}")
            # requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")

    @staticmethod
    def send_teams_alert(message: str):
        payload = {"text": f"⚠️ EDYSOR-X SLA ALERT: {message}"}
        try:
            logger.warning(f"[TEAMS ALERT] {payload['text']}")
            # requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")

    @staticmethod
    def check_sla_thresholds(incident_id: str, mttd_minutes: float, mttr_minutes: float):
        """Alerts if Mean Time to Detect > 5m or Mean Time to Respond > 10m."""
        if mttd_minutes > 5.0:
            msg = f"Incident {incident_id} breached MTTD threshold! (Took {mttd_minutes:.1f}m. Target: < 5m)"
            AlertManager.send_slack_alert(msg)
            
        if mttr_minutes > 10.0:
            msg = f"Incident {incident_id} breached MTTR threshold! (Took {mttr_minutes:.1f}m. Target: < 10m)"
            AlertManager.send_slack_alert(msg)
