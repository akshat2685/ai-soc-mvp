"""Account Takeover Detector — flags failed-then-success login patterns from new devices."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult


class ATODetector(BaseDetector):
    name = "Account Takeover Detector"
    attack_type = "ACCOUNT_TAKEOVER"
    default_threshold = 3  # failed attempts before a success

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:

        if self.has_recent_alert(source_ip, self.attack_type):
            return None

        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM logs WHERE source_ip = ? AND event_type = 'login' "
                "ORDER BY timestamp ASC",
                (source_ip,)
            )
            all_logins = [dict(r) for r in cur.fetchall()]

        if not all_logins:
            return None

        # Pattern: N failed logins followed by a success
        failed_count = 0
        ato_detected = False
        for login in all_logins:
            if login['status'] == 'failed':
                failed_count += 1
            elif login['status'] == 'success' and failed_count >= self.default_threshold:
                ato_detected = True
                break

        if not ato_detected:
            return None

        # Check if this is a new device for this user
        is_new_device = False
        target_user = next((l.get('user_id') for l in all_logins if l.get('user_id') and l['status'] == 'success'), None)
        if target_user and device_fingerprint and device_fingerprint != "unknown":
            with get_db() as conn:
                cur = conn.execute(
                    "SELECT COUNT(*) as c FROM logs WHERE user_id = ? AND device_fingerprint = ? "
                    "AND timestamp < datetime('now', '-1 hour')",
                    (target_user, device_fingerprint)
                )
                prev_usage = cur.fetchone()['c']
                is_new_device = prev_usage == 0

        # Confidence based on signals
        confidence = 60
        if is_new_device:
            confidence += 20
        if failed_count >= 5:
            confidence += 10
        if failed_count >= 10:
            confidence += 5

        citations = self.extract_citations(all_logins)
        return DetectionResult(
            title="Account Takeover",
            attack_type=self.attack_type,
            severity="HIGH",
            confidence_score=min(98, confidence),
            source_ip=source_ip,
            events=all_logins,
            device_fingerprint=device_fingerprint,
            evidence_citations=citations,
            metadata={
                "detection_method": "failed_then_success",
                "failed_attempts": failed_count,
                "target_user": target_user,
                "new_device": is_new_device,
            }
        )
