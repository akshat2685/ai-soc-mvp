"""Bot Activity Detector — flags suspicious user-agents and automated access patterns."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult


class BotDetector(BaseDetector):
    name = "Bot Activity Detector"
    attack_type = "BOT_ACTIVITY"
    default_threshold = 10

    # Suspicious user-agent patterns
    SUSPICIOUS_UA_PATTERNS = [
        'bot', 'curl', 'python', 'scanner', 'scrapy', 'httpclient',
        'wget', 'go-http', 'java/', 'libwww', 'mechanize', 'phantom',
        'headless', 'selenium', 'puppeteer', 'playwright'
    ]

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:

        if self.has_recent_alert(source_ip, self.attack_type):
            return None

        with get_db() as conn:
            # Build query for suspicious UAs
            ua_conditions = " OR ".join(
                f"user_agent LIKE '%{p}%'" for p in self.SUSPICIOUS_UA_PATTERNS
            )
            cur = conn.execute(
                f"SELECT * FROM logs WHERE source_ip = ? AND "
                f"(user_agent IS NULL OR user_agent = '' OR {ua_conditions}) "
                f"ORDER BY timestamp DESC",
                (source_ip,)
            )
            bot_events = [dict(r) for r in cur.fetchall()]

        threshold = self.get_adaptive_threshold("source_ip", source_ip, "page_view")
        if len(bot_events) >= threshold:
            # Analyze patterns for confidence
            unique_endpoints = set(e.get('endpoint', '') for e in bot_events if e.get('endpoint'))
            unique_uas = set(e.get('user_agent', '') for e in bot_events if e.get('user_agent'))
            rapid_fire = self._check_rapid_fire(bot_events)

            confidence = 50
            if not unique_uas or any(ua == '' for ua in unique_uas):
                confidence += 15  # No UA = more suspicious
            if rapid_fire:
                confidence += 20  # Rapid requests = automated
            if len(unique_endpoints) > 5:
                confidence += 10  # Hitting many endpoints = scraping

            citations = self.extract_citations(bot_events)
            return DetectionResult(
                title="Bot Activity Detected",
                attack_type=self.attack_type,
                severity="MEDIUM",
                confidence_score=min(95, confidence),
                source_ip=source_ip,
                events=bot_events,
                device_fingerprint=device_fingerprint,
                evidence_citations=citations,
                metadata={
                    "detection_method": "suspicious_ua_pattern",
                    "threshold": threshold,
                    "unique_endpoints_hit": len(unique_endpoints),
                    "user_agents": list(unique_uas)[:5],
                    "rapid_fire_detected": rapid_fire,
                }
            )
        return None

    def _check_rapid_fire(self, events: list, max_gap_seconds: float = 0.5) -> bool:
        """Check if events are suspiciously close together (< 500ms apart)."""
        if len(events) < 3:
            return False
        timestamps = []
        for e in events[:20]:
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00'))
                timestamps.append(ts)
            except (ValueError, TypeError):
                continue
        if len(timestamps) < 3:
            return False
        timestamps.sort()
        rapid_count = sum(
            1 for i in range(1, len(timestamps))
            if (timestamps[i] - timestamps[i-1]).total_seconds() < max_gap_seconds
        )
        return rapid_count >= 3
