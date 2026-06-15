"""Base detector class and detection result model."""
from dataclasses import dataclass, field
from typing import Optional
import math
from database import get_db


@dataclass
class DetectionResult:
    """Result from a detector indicating a threat was found."""
    title: str
    attack_type: str
    severity: str                # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score: int        # 0-100
    source_ip: str
    events: list                 # related log events
    device_fingerprint: str = None
    evidence_citations: list = field(default_factory=list)  # list of log IDs that support this
    metadata: dict = field(default_factory=dict)


class BaseDetector:
    """Abstract base class for all threat detectors."""

    name: str = "BaseDetector"
    attack_type: str = "UNKNOWN"
    default_threshold: int = 5

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:
        """Run detection logic. Return DetectionResult if threat found, else None."""
        raise NotImplementedError

    def get_adaptive_threshold(self, entity_field: str, entity_value: str,
                                event_type: str, status: str = None) -> int:
        """
        Computes adaptive threshold from rolling 24h window.
        Uses time-of-day and day-of-week awareness from entity_baselines table first,
        falls back to raw log counting if baseline not available.
        Returns mean + 3 * std_dev, or default_threshold as fallback.
        """
        if not entity_value:
            return self.default_threshold

        # Try entity_baselines table first (pre-computed, time-aware)
        import datetime
        now = datetime.datetime.now()
        hour = now.hour
        dow = now.weekday()

        with get_db() as conn:
            cur = conn.execute(
                "SELECT avg_count, std_dev, sample_count FROM entity_baselines "
                "WHERE entity_type = ? AND entity_value = ? AND event_type = ? "
                "AND hour_of_day = ? AND day_of_week = ?",
                (entity_field, entity_value, event_type, hour, dow)
            )
            baseline = cur.fetchone()
            if baseline and baseline['sample_count'] >= 3:
                threshold = math.ceil(baseline['avg_count'] + 3 * baseline['std_dev'])
                return max(self.default_threshold, threshold)

        # Fallback: compute from raw logs (original behavior)
        query = f"""
            SELECT COUNT(*) as cnt
            FROM logs
            WHERE {entity_field} = ? 
              AND event_type = ? 
        """
        params = [entity_value, event_type]
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " AND timestamp >= datetime('now', '-24 hours') GROUP BY strftime('%Y-%m-%d %H', timestamp)"

        with get_db() as conn:
            cur = conn.execute(query, params)
            rows = cur.fetchall()

        if not rows or len(rows) < 3:
            return self.default_threshold

        counts = [r['cnt'] for r in rows]
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = math.sqrt(variance)

        threshold = math.ceil(mean + 3 * std_dev)
        return max(self.default_threshold, threshold)

    def get_adaptive_distinct_threshold(self, user_id: str, default_val: int = 3) -> int:
        """Adaptive threshold for distinct IPs targeting a user."""
        if not user_id:
            return default_val
        query = """
            SELECT COUNT(DISTINCT source_ip) as distinct_ips_count
            FROM logs
            WHERE user_id = ?
              AND event_type = 'login'
              AND status = 'failed'
              AND timestamp >= datetime('now', '-24 hours')
            GROUP BY strftime('%Y-%m-%d %H', timestamp)
        """
        with get_db() as conn:
            cur = conn.execute(query, (user_id,))
            rows = cur.fetchall()

        if not rows or len(rows) < 3:
            return default_val

        counts = [r['distinct_ips_count'] for r in rows]
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = math.sqrt(variance)

        threshold = math.ceil(mean + 3 * std_dev)
        return max(default_val, threshold)

    def has_recent_alert(self, attacker_ip: str, attack_type: str, minutes: int = 10) -> bool:
        """Check if a similar alert was already raised recently (dedup)."""
        with get_db() as conn:
            cur = conn.execute(
                "SELECT id FROM alerts WHERE attacker_ip = ? AND attack_type = ? "
                "AND timestamp >= datetime('now', ? || ' minutes')",
                (attacker_ip, attack_type, f"-{minutes}")
            )
            return cur.fetchone() is not None

    def extract_citations(self, events: list, max_citations: int = 10) -> list:
        """Extract log entry IDs and timestamps as evidence citations."""
        citations = []
        for event in events[:max_citations]:
            if isinstance(event, dict) and 'id' in event:
                citations.append({
                    "log_id": event['id'],
                    "timestamp": event.get('timestamp', ''),
                    "event_type": event.get('event_type', ''),
                    "source_ip": event.get('source_ip', ''),
                    "status": event.get('status', ''),
                    "user_id": event.get('user_id', ''),
                })
        return citations
