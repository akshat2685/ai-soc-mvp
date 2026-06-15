"""Distributed Credential Stuffing Detector — same account targeted from many IPs."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult


class DistributedAttackDetector(BaseDetector):
    name = "Distributed Attack Detector"
    attack_type = "DISTRIBUTED_CREDENTIAL_STUFFING"
    default_threshold = 3  # distinct IPs

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:

        if not user_id:
            return None

        # Check if this user is being targeted from multiple IPs
        with get_db() as conn:
            cur = conn.execute(
                "SELECT DISTINCT source_ip FROM logs "
                "WHERE user_id = ? AND event_type = 'login' AND status = 'failed' "
                "AND timestamp >= datetime('now', '-1 hour')",
                (user_id,)
            )
            distinct_ips = [r["source_ip"] for r in cur.fetchall()]

        threshold = self.get_adaptive_distinct_threshold(user_id, self.default_threshold)
        if len(distinct_ips) < threshold:
            return None

        # Already alerted for this user recently?
        with get_db() as conn:
            cur = conn.execute(
                "SELECT id FROM alerts WHERE attack_type = ? AND evidence LIKE ? "
                "AND timestamp >= datetime('now', '-10 minutes')",
                (self.attack_type, f"%{user_id}%")
            )
            if cur.fetchone():
                return None

        # Gather all distributed events
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM logs WHERE user_id = ? AND event_type = 'login' "
                "AND status = 'failed' AND timestamp >= datetime('now', '-1 hour') "
                "ORDER BY timestamp DESC",
                (user_id,)
            )
            distributed_events = [dict(r) for r in cur.fetchall()]

        # Higher confidence with more IPs
        confidence = 50 + min(40, len(distinct_ips) * 8)

        citations = self.extract_citations(distributed_events)
        return DetectionResult(
            title=f"Distributed Credential Stuffing targeting {user_id}",
            attack_type=self.attack_type,
            severity="HIGH",
            confidence_score=min(98, confidence),
            source_ip=source_ip,
            events=distributed_events,
            device_fingerprint=device_fingerprint,
            evidence_citations=citations,
            metadata={
                "detection_method": "distributed_ips",
                "target_user": user_id,
                "distinct_ips": distinct_ips,
                "ip_count": len(distinct_ips),
                "threshold": threshold,
            }
        )
