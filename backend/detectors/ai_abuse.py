"""Detector for AI-Specific Threats (Prompt Injection, Model/API Key Abuse)."""
from typing import Optional
from database import get_db
from .base import BaseDetector, DetectionResult
import re

class AIAbuseDetector(BaseDetector):
    name = "AIAbuseDetector"
    attack_type = "AI_ABUSE"
    default_threshold = 50  # Default threshold for AI API calls per minute

    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore previous instructions",
        r"(?i)system prompt",
        r"(?i)bypass restrictions",
        r"(?i)you are now",
        r"(?i)jailbreak",
        r"(?i)disregard all prior",
    ]

    def detect(self, source_ip: str, user_id: str, device_fingerprint: str,
               user_agent: str = None, headers: dict = None) -> Optional[DetectionResult]:
        
        # 1. Check for Prompt Injection in headers or user agent
        # (In a real system, we'd also check the payload body, but we only have headers/endpoint in this log struct)
        injection_found = False
        suspicious_string = ""
        
        check_strings = [user_agent or ""]
        if headers:
            check_strings.extend(str(v) for v in headers.values())
            
        for s in check_strings:
            for pattern in self.PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, s):
                    injection_found = True
                    suspicious_string = s
                    break
            if injection_found:
                break
                
        if injection_found:
            if self.has_recent_alert(source_ip, "PROMPT_INJECTION", minutes=10):
                return None
                
            with get_db() as conn:
                # fetch the exact log that triggered this (assuming it's the latest one from this IP)
                conn.row_factory = dict_factory
                cur = conn.execute(
                    "SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 1",
                    (source_ip,)
                )
                events = cur.fetchall()

            return DetectionResult(
                title=f"Prompt Injection Attempt from {source_ip}",
                attack_type="PROMPT_INJECTION",
                severity="HIGH",
                confidence_score=95,
                source_ip=source_ip,
                events=events,
                device_fingerprint=device_fingerprint,
                evidence_citations=self.extract_citations(events),
                metadata={"suspicious_payload": suspicious_string}
            )

        # 2. Check for AI Model / API Key Quota Abuse
        # We look for a massive spike in 'api_call' events targeting typical AI endpoints
        with get_db() as conn:
            conn.row_factory = dict_factory
            cur = conn.execute(
                """
                SELECT * FROM logs 
                WHERE source_ip = ? 
                  AND event_type = 'api_call' 
                  AND (endpoint LIKE '%/generate%' OR endpoint LIKE '%/chat%' OR endpoint LIKE '%/embed%')
                  AND timestamp >= datetime('now', '-1 minute')
                ORDER BY timestamp DESC
                """,
                (source_ip,)
            )
            events = cur.fetchall()

        if len(events) >= self.default_threshold:
            if self.has_recent_alert(source_ip, "AI_MODEL_ABUSE", minutes=30):
                return None

            return DetectionResult(
                title=f"AI Model API Abuse from {source_ip}",
                attack_type="AI_MODEL_ABUSE",
                severity="HIGH",
                confidence_score=85,
                source_ip=source_ip,
                events=events,
                device_fingerprint=device_fingerprint,
                evidence_citations=self.extract_citations(events),
                metadata={"calls_per_minute": len(events)}
            )

        return None

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d
