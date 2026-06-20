"""Alerting Notifier.

Sends alert notifications (Slack, Teams, Email, Generic Webhook) when the system
detects operational anomalies (e.g., high error rates, latency spikes).
"""
from __future__ import annotations

import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Dict, Any, Optional
import requests

log = logging.getLogger(__name__)

# Load config from environment variables
SLACK_WEBHOOK_URL = os.environ.get("ALERT_SLACK_WEBHOOK", "")
TEAMS_WEBHOOK_URL = os.environ.get("ALERT_TEAMS_WEBHOOK", "")
GENERIC_WEBHOOK_URL = os.environ.get("ALERT_GENERIC_WEBHOOK", "")

# Email settings
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 25))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "soc-alerts@shieldai.local")
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", "soc-ops@shieldai.local")

# Latency and Error Thresholds
LATENCY_THRESHOLD_SEC = float(os.environ.get("ALERT_LATENCY_THRESHOLD_SEC", 3.0))
ERROR_RATE_THRESHOLD = int(os.environ.get("ALERT_ERROR_RATE_THRESHOLD", 10))


def send_slack_alert(subject: str, message: str, level: str = "WARNING") -> bool:
    """Send alert to Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        return False
    
    color = "#FF0000" if level.upper() == "CRITICAL" else "#FFA500" if level.upper() == "WARNING" else "#00FF00"
    payload = {
        "attachments": [
            {
                "fallback": f"[{level}] {subject}: {message}",
                "color": color,
                "title": f"[{level}] {subject}",
                "text": message,
                "fields": [
                    {
                        "title": "Service",
                        "value": "EDYSOR SOC Engine",
                        "short": True
                    }
                ]
            }
        ]
    }
    try:
        r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        return r.status_code == 200
    except Exception as e:
        log.warning("Failed to send Slack alert: %s", e)
        return False


def send_teams_alert(subject: str, message: str, level: str = "WARNING") -> bool:
    """Send alert to Microsoft Teams webhook."""
    if not TEAMS_WEBHOOK_URL:
        return False
    
    theme_color = "FF0000" if level.upper() == "CRITICAL" else "FFA500" if level.upper() == "WARNING" else "00FF00"
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": subject,
        "sections": [{
            "activityTitle": f"[{level}] {subject}",
            "activitySubtitle": "EDYSOR SOC Ops Alert",
            "text": message
        }]
    }
    try:
        r = requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=5)
        return r.status_code == 200
    except Exception as e:
        log.warning("Failed to send Teams alert: %s", e)
        return False


def send_email_alert(subject: str, message: str, level: str = "WARNING") -> bool:
    """Send alert via SMTP email."""
    if not ALERT_EMAIL_TO:
        return False
        
    msg = MIMEText(message)
    msg["Subject"] = f"[{level}] {subject}"
    msg["From"] = ALERT_EMAIL_FROM
    msg["To"] = ALERT_EMAIL_TO
    
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USER and SMTP_PASSWORD:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())
        return True
    except Exception as e:
        log.warning("Failed to send email alert: %s", e)
        return False


def send_generic_webhook(subject: str, message: str, level: str = "WARNING") -> bool:
    """Send alert to generic webhook endpoint."""
    if not GENERIC_WEBHOOK_URL:
        return False
    
    payload = {
        "event": "soc_ops_alert",
        "level": level.upper(),
        "subject": subject,
        "message": message,
        "timestamp": requests.utils.default_headers().get("Date", "")
    }
    try:
        r = requests.post(GENERIC_WEBHOOK_URL, json=payload, timeout=5)
        return r.status_code in (200, 201, 202)
    except Exception as e:
        log.warning("Failed to send generic webhook alert: %s", e)
        return False


def send_alert(subject: str, message: str, level: str = "WARNING") -> None:
    """Dispatches alerts across all configured channels."""
    log.info("Dispatching %s alert: %s", level, subject)
    
    send_slack_alert(subject, message, level)
    send_teams_alert(subject, message, level)
    send_email_alert(subject, message, level)
    send_generic_webhook(subject, message, level)


def check_metrics_and_notify(
    component: str,
    error_count: float,
    latency_avg: float
) -> None:
    """Checks latency and error counts against thresholds and raises alerts if exceeded."""
    if error_count >= ERROR_RATE_THRESHOLD:
        subject = f"High Error Rate Detected in {component}"
        message = f"Component '{component}' has registered {error_count} errors in the current window. This exceeds the threshold of {ERROR_RATE_THRESHOLD}."
        send_alert(subject, message, level="CRITICAL")
        
    if latency_avg >= LATENCY_THRESHOLD_SEC:
        subject = f"Latency Spike Detected in {component}"
        message = f"Component '{component}' average latency has reached {latency_avg:.2f}s, exceeding the limit of {LATENCY_THRESHOLD_SEC}s."
        send_alert(subject, message, level="WARNING")
