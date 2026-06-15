"""Credential Stuffing Detector — detects brute-force login attempts by IP and device fingerprint."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult


class CredentialStuffingDetector(BaseDetector):
    name = "Credential Stuffing Detector"
    attack_type = "CREDENTIAL_STUFFING"
    default_threshold = 5

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:

        if self.has_recent_alert(source_ip, self.attack_type):
            return None

        # Check by IP
        result = self._check_by_ip(source_ip, device_fingerprint)
        if result:
            return result

        # Check by device fingerprint (catches IP rotation)
        if device_fingerprint and device_fingerprint != "unknown":
            result = self._check_by_fingerprint(source_ip, device_fingerprint)
            if result:
                return result

        return None

    def _check_by_ip(self, source_ip: str, device_fingerprint: str) -> Optional[DetectionResult]:
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM logs WHERE source_ip = ? AND event_type = 'login' "
                "AND status = 'failed' ORDER BY timestamp DESC",
                (source_ip,)
            )
            failed_logins = [dict(r) for r in cur.fetchall()]

        threshold = self.get_adaptive_threshold("source_ip", source_ip, "login", "failed")
        if len(failed_logins) >= threshold:
            citations = self.extract_citations(failed_logins)
            return DetectionResult(
                title="Credential Stuffing",
                attack_type=self.attack_type,
                severity="HIGH",
                confidence_score=min(95, 60 + len(failed_logins) * 3),
                source_ip=source_ip,
                events=failed_logins,
                device_fingerprint=device_fingerprint,
                evidence_citations=citations,
                metadata={"detection_method": "ip_failed_logins", "threshold": threshold}
            )
        return None

    def _check_by_fingerprint(self, source_ip: str, device_fingerprint: str) -> Optional[DetectionResult]:
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM logs WHERE device_fingerprint = ? AND event_type = 'login' "
                "AND status = 'failed' ORDER BY timestamp DESC",
                (device_fingerprint,)
            )
            failed_logins = [dict(r) for r in cur.fetchall()]

        threshold = self.get_adaptive_threshold("device_fingerprint", device_fingerprint, "login", "failed")
        if len(failed_logins) >= threshold:
            # Check how many distinct IPs used this fingerprint
            distinct_ips = set(e.get('source_ip', '') for e in failed_logins)
            citations = self.extract_citations(failed_logins)
            return DetectionResult(
                title=f"Credential Stuffing via rotated IPs ({len(distinct_ips)} IPs)",
                attack_type=self.attack_type,
                severity="HIGH",
                confidence_score=min(98, 65 + len(distinct_ips) * 5),
                source_ip=source_ip,
                events=failed_logins,
                device_fingerprint=device_fingerprint,
                evidence_citations=citations,
                metadata={
                    "detection_method": "fingerprint_rotation",
                    "distinct_ips": list(distinct_ips),
                    "threshold": threshold
                }
            )
        return None
