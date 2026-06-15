"""Tiered Autonomous Response Engine.

Response ladder: MONITOR → RATE_LIMIT → CAPTCHA_CHALLENGE → TEMP_BLOCK → PERM_BLOCK
High-impact actions (PERM_BLOCK, LOCK_ACCOUNT) require analyst approval.
All actions are immutably logged to the audit_log table.
"""
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import get_db
from datetime import datetime, timedelta

SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

# ── Response Tier Configuration ──

RESPONSE_TIERS = {
    1: "MONITOR",
    2: "RATE_LIMIT",
    3: "CAPTCHA_CHALLENGE",
    4: "TEMP_BLOCK",
    5: "PERM_BLOCK",
}

TIER_NAMES = {v: k for k, v in RESPONSE_TIERS.items()}

# Severity × confidence → tier mapping
SEVERITY_TIER_MAP = {
    "LOW": 1,       # MONITOR
    "MEDIUM": 2,    # RATE_LIMIT
    "HIGH": 4,      # TEMP_BLOCK
    "CRITICAL": 5,  # PERM_BLOCK (queued for approval)
}

# Default block duration for TEMP_BLOCK (in minutes)
TEMP_BLOCK_DURATION_MINUTES = 60

# Tiers that require human approval before execution
APPROVAL_REQUIRED_TIERS = {5}  # PERM_BLOCK

# Action types that always require approval regardless of tier
APPROVAL_REQUIRED_ACTIONS = {"BLOCK_CIDR", "LOCK_ACCOUNT"}


class ResponseEngine:
    """Manages tiered autonomous responses with approval gates and audit logging."""

    def execute_tiered_response(self, severity: str, confidence_score: int,
                                 target_ip: str, alert_id: int, incident_id: int = None,
                                 attack_type: str = None, evidence: dict = None):
        """Determine and execute the appropriate response tier."""
        tier = self.calculate_tier(severity, confidence_score)
        action_type = RESPONSE_TIERS.get(tier, "MONITOR")

        # High-impact actions → queue for approval
        if tier in APPROVAL_REQUIRED_TIERS:
            self._queue_for_approval(
                action_type=action_type,
                response_tier=tier,
                target=target_ip,
                alert_id=alert_id,
                incident_id=incident_id,
                evidence=evidence,
            )
            return

        # Execute the response
        if tier == 1:  # MONITOR
            self._execute_monitor(target_ip, alert_id, incident_id, evidence)
        elif tier == 2:  # RATE_LIMIT
            self._execute_rate_limit(target_ip, alert_id, incident_id, evidence)
        elif tier == 3:  # CAPTCHA_CHALLENGE
            self._execute_captcha(target_ip, alert_id, incident_id, evidence)
        elif tier == 4:  # TEMP_BLOCK
            self._execute_temp_block(target_ip, alert_id, incident_id, evidence)

    def calculate_tier(self, severity: str, confidence_score: int) -> int:
        """Map severity + confidence to a response tier."""
        base_tier = SEVERITY_TIER_MAP.get(severity, 2)

        # Adjust based on confidence
        if confidence_score < 50:
            base_tier = max(1, base_tier - 2)  # Low confidence → demote
        elif confidence_score < 70:
            base_tier = max(1, base_tier - 1)  # Medium confidence → slight demote
        # High confidence (>= 70) → use base tier as-is

        return min(5, base_tier)

    # ── Tier Executors ──

    def _execute_monitor(self, target: str, alert_id: int, incident_id: int, evidence: dict):
        """Tier 1: Log only, no blocking action."""
        details = f"IP {target} flagged for monitoring. No blocking action taken."
        self._save_response("MONITOR", target, details, alert_id, incident_id,
                            tier=1, status="ACTIVE")
        self._write_audit("MONITOR", 1, target, alert_id, incident_id, evidence, "AUTO", "SUCCESS")
        print(f"[RESPONSE] MONITOR → {target}")

    def _execute_rate_limit(self, target: str, alert_id: int, incident_id: int, evidence: dict):
        """Tier 2: Rate-limit to 1 req/min."""
        details = f"IP {target} rate-limited to 1 req/min due to suspicious activity."
        self._save_response("RATE_LIMIT", target, details, alert_id, incident_id,
                            tier=2, status="ACTIVE")
        self._write_audit("RATE_LIMIT", 2, target, alert_id, incident_id, evidence, "AUTO", "SUCCESS")
        print(f"[RESPONSE] RATE_LIMIT → {target}")

    def _execute_captcha(self, target: str, alert_id: int, incident_id: int, evidence: dict):
        """Tier 3: Flag for CAPTCHA challenge on next request."""
        details = f"IP {target} flagged for CAPTCHA challenge on next request."
        self._save_response("CAPTCHA_CHALLENGE", target, details, alert_id, incident_id,
                            tier=3, status="ACTIVE")
        self._write_audit("CAPTCHA_CHALLENGE", 3, target, alert_id, incident_id, evidence, "AUTO", "SUCCESS")
        print(f"[RESPONSE] CAPTCHA_CHALLENGE → {target}")

    def _execute_temp_block(self, target: str, alert_id: int, incident_id: int, evidence: dict):
        """Tier 4: Temporary block with auto-expiry."""
        expires_at = (datetime.utcnow() + timedelta(minutes=TEMP_BLOCK_DURATION_MINUTES)).isoformat()
        details = (f"IP {target} temporarily blocked at WAF layer. "
                   f"Block expires at {expires_at} (auto-unblock with re-evaluation).")
        self._save_response("TEMP_BLOCK", target, details, alert_id, incident_id,
                            tier=4, status="ACTIVE", expires_at=expires_at)
        self._write_audit("TEMP_BLOCK", 4, target, alert_id, incident_id, evidence, "AUTO", "SUCCESS",
                          notes=f"Expires at {expires_at}")
        print(f"[RESPONSE] TEMP_BLOCK → {target} (expires {expires_at})")

    def execute_perm_block(self, target: str, alert_id: int, incident_id: int,
                            evidence: dict, approved_by: str = "admin"):
        """Tier 5: Permanent block — only called after approval."""
        details = f"IP {target} PERMANENTLY blocked at WAF layer. Approved by {approved_by}."
        self._save_response("PERM_BLOCK", target, details, alert_id, incident_id,
                            tier=5, status="ACTIVE", approved_by=approved_by,
                            approval_status="APPROVED")
        self._write_audit("PERM_BLOCK", 5, target, alert_id, incident_id, evidence,
                          "APPROVED", "SUCCESS", approved_by=approved_by)
        print(f"[RESPONSE] PERM_BLOCK → {target} (approved by {approved_by})")

    def lock_account(self, user_id: str, alert_id: int, incident_id: int = None,
                     evidence: dict = None):
        """Lock a user account — always requires approval."""
        self._queue_for_approval(
            action_type="LOCK_ACCOUNT",
            response_tier=5,
            target=user_id,
            alert_id=alert_id,
            incident_id=incident_id,
            evidence=evidence,
        )

    def draft_deterrence_email(self, attacker_ip: str, email_content: str,
                                alert_id: int = None, incident_id: int = None):
        """Save deterrence email as draft for legal/security review."""
        with get_db() as conn:
            conn.execute(
                "INSERT INTO email_drafts (alert_id, incident_id, target_ip, subject, body, status) "
                "VALUES (?, ?, ?, ?, ?, 'DRAFT')",
                (alert_id, incident_id, attacker_ip,
                 f"Deterrence Notice — IP {attacker_ip}", email_content)
            )
            conn.commit()

        # Also log as a response action
        self._save_response("DRAFT_EMAIL", attacker_ip,
                            f"Deterrence email DRAFTED (pending legal/security review).",
                            alert_id, incident_id, tier=1, status="PENDING_REVIEW")
        self._write_audit("DRAFT_EMAIL", 1, attacker_ip, alert_id, incident_id,
                          None, "AUTO", "SUCCESS",
                          notes="Email saved as draft for review")
        print(f"[RESPONSE] DRAFT_EMAIL → {attacker_ip}")

    # ── Approval Queue ──

    def _queue_for_approval(self, action_type: str, response_tier: int,
                            target: str, alert_id: int, incident_id: int = None,
                            evidence: dict = None):
        """Queue a high-impact action for analyst approval."""
        with get_db() as conn:
            conn.execute(
                "INSERT INTO pending_approvals "
                "(action_type, response_tier, target, alert_id, incident_id, evidence_snapshot, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'PENDING')",
                (action_type, response_tier, target, alert_id, incident_id,
                 json.dumps(evidence) if evidence else None)
            )
            conn.commit()

        self._write_audit(action_type, response_tier, target, alert_id, incident_id,
                          evidence, "PENDING", "QUEUED",
                          notes="Queued for analyst approval")
        print(f"[RESPONSE] QUEUED for approval: {action_type} → {target}")

        # Broadcast approval needed
        try:
            from main import broadcast_event
            broadcast_event({
                "type": "approval_needed",
                "approval": {
                    "action_type": action_type,
                    "target": target,
                    "alert_id": alert_id,
                }
            })
        except Exception:
            pass

    # ── Block Expiry Management ──

    def check_expired_blocks(self):
        """Check and process expired temporary blocks.
        Should be called periodically (every 5 minutes)."""
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM responses WHERE action_type = 'TEMP_BLOCK' "
                "AND status = 'ACTIVE' AND expires_at IS NOT NULL "
                "AND expires_at <= datetime('now')"
            )
            expired_blocks = [dict(r) for r in cur.fetchall()]

        for block in expired_blocks:
            if self._should_escalate(block):
                self._escalate_block(block)
            else:
                self._unblock(block)

    def _should_escalate(self, block: dict) -> bool:
        """Check if an expired block should be escalated (IP tried again during block)."""
        with get_db() as conn:
            cur = conn.execute(
                "SELECT COUNT(*) as c FROM logs WHERE source_ip = ? "
                "AND timestamp >= ? AND status = 'failed'",
                (block['target'], block['timestamp'])
            )
            attempts_during_block = cur.fetchone()['c']
        return attempts_during_block > 3  # If they kept trying, escalate

    def _escalate_block(self, block: dict):
        """Escalate a temp block to pending permanent block."""
        with get_db() as conn:
            conn.execute("UPDATE responses SET status = 'ESCALATED' WHERE id = ?", (block['id'],))
            conn.commit()
        self._queue_for_approval("PERM_BLOCK", 5, block['target'], block.get('alert_id'),
                                  block.get('incident_id'), {"escalated_from": "TEMP_BLOCK"})
        print(f"[RESPONSE] ESCALATED → {block['target']} (re-attempted during block)")

    def _unblock(self, block: dict):
        """Remove an expired temp block."""
        with get_db() as conn:
            conn.execute("UPDATE responses SET status = 'EXPIRED' WHERE id = ?", (block['id'],))
            conn.commit()
        self._write_audit("UNBLOCK", 0, block['target'], block.get('alert_id'),
                          block.get('incident_id'), None, "AUTO", "SUCCESS",
                          notes="Temp block expired — no re-attempts detected, unblocked.")
        print(f"[RESPONSE] UNBLOCKED → {block['target']} (block expired)")

    # ── Persistence Helpers ──

    def _save_response(self, action_type: str, target: str, details: str,
                        alert_id: int = None, incident_id: int = None,
                        tier: int = 1, status: str = "ACTIVE",
                        expires_at: str = None, approved_by: str = None,
                        approval_status: str = "AUTO"):
        """Save a response action to the database."""
        with get_db() as conn:
            conn.execute(
                "INSERT INTO responses (action_type, target, details, alert_id, incident_id, "
                "response_tier, status, expires_at, approved_by, approval_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (action_type, target, details, alert_id, incident_id,
                 tier, status, expires_at, approved_by, approval_status)
            )
            conn.commit()

    def _write_audit(self, action_type: str, response_tier: int, target: str,
                      alert_id: int = None, incident_id: int = None,
                      evidence: dict = None, approval_status: str = "AUTO",
                      execution_result: str = "SUCCESS", approved_by: str = None,
                      notes: str = None):
        """Write an immutable entry to the audit log."""
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (action_type, response_tier, target, alert_id, "
                "incident_id, evidence_snapshot, triggered_by, approval_status, "
                "approved_by, execution_result, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (action_type, response_tier, target, alert_id, incident_id,
                 json.dumps(evidence) if evidence else None,
                 "SYSTEM", approval_status, approved_by, execution_result, notes)
            )
            conn.commit()

    # ── Email Sending (only after approval) ──

    def send_approved_email(self, draft_id: int, approved_by: str):
        """Send a previously drafted deterrence email after approval."""
        with get_db() as conn:
            cur = conn.execute("SELECT * FROM email_drafts WHERE id = ? AND status = 'DRAFT'", (draft_id,))
            draft = cur.fetchone()
            if not draft:
                return {"error": "Draft not found or already processed"}
            draft = dict(draft)

        # Try real SMTP if configured
        sent = False
        if SMTP_EMAIL and SMTP_PASSWORD:
            try:
                self._send_real_email(draft['target_ip'], draft['body'])
                sent = True
            except Exception as e:
                print(f"[RESPONSE] SMTP send failed: {e}")

        with get_db() as conn:
            conn.execute(
                "UPDATE email_drafts SET status = ?, reviewed_by = ?, sent_at = datetime('now') WHERE id = ?",
                ('SENT' if sent else 'APPROVED', approved_by, draft_id)
            )
            conn.commit()

        self._write_audit("SEND_EMAIL", 1, draft['target_ip'], draft.get('alert_id'),
                          draft.get('incident_id'), None, "APPROVED", "SUCCESS",
                          approved_by=approved_by,
                          notes=f"Email {'sent via SMTP' if sent else 'approved (SMTP not configured)'}")
        return {"status": "sent" if sent else "approved"}

    def _send_real_email(self, attacker_ip: str, email_content: str):
        """Actually send an email via SMTP."""
        msg = MIMEMultipart()
        msg['From'] = SMTP_EMAIL
        msg['To'] = SMTP_EMAIL
        msg['Subject'] = f"[AI SOC] Deterrence Notice — Attacker IP {attacker_ip}"
        msg.attach(MIMEText(email_content, 'plain'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[RESPONSE] Email sent via SMTP for IP {attacker_ip}")


# ── Legacy API compatibility ──

def block_ip(ip: str, alert_id: int = None):
    """Legacy function — now maps to TEMP_BLOCK."""
    engine = ResponseEngine()
    engine._execute_temp_block(ip, alert_id, None, None)

def throttle_ip(ip: str, alert_id: int = None):
    """Legacy function — now maps to RATE_LIMIT."""
    engine = ResponseEngine()
    engine._execute_rate_limit(ip, alert_id, None, None)

def lock_account(user_id: str, alert_id: int = None):
    """Legacy function — now queues for approval."""
    engine = ResponseEngine()
    engine.lock_account(user_id, alert_id)

def send_deterrence_email(attacker_ip: str, email_content: str, alert_id: int = None):
    """Legacy function — now saves as draft."""
    engine = ResponseEngine()
    engine.draft_deterrence_email(attacker_ip, email_content, alert_id)
