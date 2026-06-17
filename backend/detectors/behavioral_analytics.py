"""Detector for Behavioral Analytics (Z-Score anomalies)."""
from typing import Optional
import math
from database import get_db
from .base import BaseDetector, DetectionResult

class BehavioralAnomalyDetector(BaseDetector):
    name = "BehavioralAnomalyDetector"
    attack_type = "BEHAVIORAL_ANOMALY"
    
    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:
        
        # We need an entity to track. We prefer user_id, fallback to source_ip
        entity_field = "user_id" if user_id else "source_ip"
        entity_value = user_id if user_id else source_ip
        
        if not entity_value:
            return None

        # Check if we already alerted on this entity recently to avoid spam
        if self.has_recent_alert(source_ip, self.attack_type, minutes=60):
            return None

        with get_db() as conn:
            conn.row_factory = dict_factory
            
            # 1. Get the current volume for the last 10 minutes
            cur = conn.execute(
                f"""
                SELECT COUNT(*) as current_count, MAX(timestamp) as last_seen 
                FROM logs 
                WHERE {entity_field} = ? 
                  AND timestamp >= datetime('now', '-10 minutes')
                """,
                (entity_value,)
            )
            current_stats = cur.fetchone()
            current_count = current_stats['current_count'] if current_stats else 0
            
            # If volume is extremely low anyway, don't trigger (prevents 0 -> 2 spikes)
            if current_count < 20:
                return None

            # 2. Get the historical baseline (count per 10-min windows over the last 24h)
            cur = conn.execute(
                f"""
                SELECT strftime('%Y-%m-%d %H:%M', timestamp, '-10 minutes') as window, COUNT(*) as cnt
                FROM logs
                WHERE {entity_field} = ?
                  AND timestamp >= datetime('now', '-24 hours')
                  AND timestamp < datetime('now', '-10 minutes')
                GROUP BY window
                """,
                (entity_value,)
            )
            rows = cur.fetchall()

        if not rows or len(rows) < 3:
            return None

        counts = [r['cnt'] for r in rows]
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = math.sqrt(variance)

        # Z-Score formula: (X - Mean) / StdDev
        # If std_dev is 0, any deviation > 0 is anomalous, but we add a tiny epsilon to prevent div by 0
        z_score = (current_count - mean) / (std_dev if std_dev > 0 else 0.1)

        # Alert if Z-Score > 3 (3 standard deviations above the mean)
        if z_score > 3.0:
            with get_db() as conn:
                conn.row_factory = dict_factory
                cur = conn.execute(
                    f"SELECT * FROM logs WHERE {entity_field} = ? AND timestamp >= datetime('now', '-10 minutes') ORDER BY timestamp DESC LIMIT 50",
                    (entity_value,)
                )
                events = cur.fetchall()

            return DetectionResult(
                title=f"Behavioral Anomaly: Volume Spike for {entity_value}",
                attack_type=self.attack_type,
                severity="MEDIUM",
                confidence_score=min(100, int(70 + (z_score * 2))),  # Scales up with z-score
                source_ip=source_ip,
                events=events,
                device_fingerprint=device_fingerprint,
                evidence_citations=self.extract_citations(events),
                metadata={
                    "entity": entity_value,
                    "z_score": round(z_score, 2),
                    "current_10m_volume": current_count,
                    "historical_10m_mean": round(mean, 2)
                }
            )

        return None

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d
