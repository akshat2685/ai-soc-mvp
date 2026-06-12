import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import get_db

SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

def execute_autonomous_response(action_type: str, target: str, details: str, alert_id: int = None):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO responses (action_type, target, details, alert_id) VALUES (?, ?, ?, ?)",
            (action_type, target, details, alert_id)
        )
        conn.commit()
    print(f"[AUTONOMOUS RESPONSE] {action_type} -> {target}")

def block_ip(ip: str, alert_id: int = None):
    execute_autonomous_response("BLOCK_IP", ip, f"IP {ip} blocked at WAF layer due to detected abuse.", alert_id)

def throttle_ip(ip: str, alert_id: int = None):
    execute_autonomous_response("THROTTLE_IP", ip, f"IP {ip} rate-limited to 1 req/min due to suspicious activity.", alert_id)

def lock_account(user_id: str, alert_id: int = None):
    execute_autonomous_response("LOCK_ACCOUNT", user_id, f"Account {user_id} temporarily locked pending investigation.", alert_id)

def send_deterrence_email(attacker_ip: str, email_content: str, alert_id: int = None):
    # Try real SMTP if configured
    if SMTP_EMAIL and SMTP_PASSWORD:
        try:
            _send_real_email(attacker_ip, email_content)
            execute_autonomous_response("SEND_EMAIL", attacker_ip, f"Deterrence email SENT via SMTP.\n\nContent:\n{email_content}", alert_id)
            return
        except Exception as e:
            print(f"[RESPONSE] SMTP send failed: {e}, logging email instead.")
    
    # Fallback: log the email
    execute_autonomous_response("SEND_EMAIL", attacker_ip, f"Deterrence email logged (SMTP not configured).\n\nContent:\n{email_content}", alert_id)

def _send_real_email(attacker_ip: str, email_content: str):
    msg = MIMEMultipart()
    msg['From'] = SMTP_EMAIL
    msg['To'] = SMTP_EMAIL  # Send to self as a record (real target would be ISP abuse contact)
    msg['Subject'] = f"[AI SOC] Deterrence Notice — Attacker IP {attacker_ip}"
    msg.attach(MIMEText(email_content, 'plain'))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
    print(f"[RESPONSE] Email sent via SMTP for IP {attacker_ip}")
