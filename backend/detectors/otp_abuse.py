"""OTP / SMS Pumping Abuse Detector."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult


class OTPAbuseDetector(BaseDetector):
    name = "OTP Abuse Detector"
    attack_type = "OTP_ABUSE"
    default_threshold = 3

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:

        if self.has_recent_alert(source_ip, self.attack_type):
            return None

        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM logs WHERE source_ip = ? AND event_type = 'otp_request' "
                "ORDER BY timestamp DESC",
                (source_ip,)
            )
            otp_requests = [dict(r) for r in cur.fetchall()]

        threshold = self.get_adaptive_threshold("source_ip", source_ip, "otp_request")
        if len(otp_requests) >= threshold:
            # Calculate cost estimate (each OTP = ~$0.01-0.05 SMS)
            est_cost = len(otp_requests) * 0.03
            citations = self.extract_citations(otp_requests)
            return DetectionResult(
                title="OTP Pumping / SMS Abuse",
                attack_type=self.attack_type,
                severity="HIGH",
                confidence_score=min(95, 65 + len(otp_requests) * 5),
                source_ip=source_ip,
                events=otp_requests,
                device_fingerprint=device_fingerprint,
                evidence_citations=citations,
                metadata={
                    "detection_method": "otp_volume",
                    "threshold": threshold,
                    "estimated_sms_cost": f"${est_cost:.2f}"
                }
            )
        return None
