"""Coupon / Business Logic Abuse Detector."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult


class CouponAbuseDetector(BaseDetector):
    name = "Coupon Abuse Detector"
    attack_type = "BUSINESS_LOGIC"
    default_threshold = 3

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:

        if not user_id:
            return None

        if self.has_recent_alert(source_ip, self.attack_type):
            return None

        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM logs WHERE user_id = ? AND event_type = 'coupon_apply' "
                "ORDER BY timestamp DESC",
                (user_id,)
            )
            coupon_events = [dict(r) for r in cur.fetchall()]

        if not coupon_events:
            return None

        threshold = self.get_adaptive_threshold("user_id", user_id, "coupon_apply")
        if len(coupon_events) >= threshold:
            # Check if they also have multiple accounts from same device/IP
            multi_account = self._check_multi_account(source_ip, device_fingerprint)
            
            confidence = 55
            if len(coupon_events) >= threshold * 2:
                confidence += 15
            if multi_account:
                confidence += 20

            citations = self.extract_citations(coupon_events)
            return DetectionResult(
                title="Business Logic Abuse — Coupon Fraud",
                attack_type=self.attack_type,
                severity="MEDIUM",
                confidence_score=min(95, confidence),
                source_ip=source_ip,
                events=coupon_events,
                device_fingerprint=device_fingerprint,
                evidence_citations=citations,
                metadata={
                    "detection_method": "coupon_volume",
                    "threshold": threshold,
                    "target_user": user_id,
                    "multi_account_suspected": multi_account,
                }
            )
        return None

    def _check_multi_account(self, source_ip: str, device_fingerprint: str) -> bool:
        """Check if multiple user accounts are using coupons from same IP or device."""
        with get_db() as conn:
            # By IP
            cur = conn.execute(
                "SELECT COUNT(DISTINCT user_id) as c FROM logs "
                "WHERE source_ip = ? AND event_type = 'coupon_apply'",
                (source_ip,)
            )
            ip_users = cur.fetchone()['c']
            if ip_users >= 3:
                return True

            # By fingerprint
            if device_fingerprint and device_fingerprint != "unknown":
                cur = conn.execute(
                    "SELECT COUNT(DISTINCT user_id) as c FROM logs "
                    "WHERE device_fingerprint = ? AND event_type = 'coupon_apply'",
                    (device_fingerprint,)
                )
                fp_users = cur.fetchone()['c']
                if fp_users >= 3:
                    return True

        return False
