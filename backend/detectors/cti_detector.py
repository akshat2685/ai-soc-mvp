from .base import BaseDetector, DetectionResult
from database import get_db

class CtiDetector(BaseDetector):
    """Detects traffic matching the Global Threat Intelligence IOC feeds."""
    name = "CtiDetector"

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str, user_agent: str = None, headers: dict = None):
        if not source_ip:
            return None

        # Prevent duplicate alerts
        if self.has_recent_alert(source_ip, "KNOWN_MALICIOUS_IP", minutes=60):
            return None

        with get_db() as conn:
            # Check if IP matches the global IOC blacklist
            cur = conn.execute(
                "SELECT source, threat_tags FROM global_ioc_feed WHERE ioc_value = ? LIMIT 1",
                (source_ip,)
            )
            row = cur.fetchone()
            
            if row:
                source = row["source"]
                tags = row["threat_tags"]
                
                # Fetch recent logs for evidence
                cur = conn.execute(
                    "SELECT id, timestamp, event_type, endpoint, user_agent FROM logs WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 10",
                    (source_ip,)
                )
                events = [dict(r) for r in cur.fetchall()]
                
                return DetectionResult(
                    title=f"CTI Match: Known Malicious IP ({source})",
                    attack_type="KNOWN_MALICIOUS_IP",
                    severity="CRITICAL",  # High severity because it's on a global blacklist
                    source_ip=source_ip,
                    confidence_score=95,  # High confidence
                    events=events,
                    device_fingerprint=device_fingerprint,
                    evidence_citations=[
                        f"IP {source_ip} was found on the {source} global threat feed.",
                        f"Associated Threat Tags: {tags}"
                    ]
                )

        return None
