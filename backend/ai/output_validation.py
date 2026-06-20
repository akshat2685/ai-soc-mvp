"""EDYSOR LLM Output Validation & Sanitization.

Provides:
  - AI-generated content validation (summaries, remediation steps, rules)
  - Suspicious command/code detection in remediation outputs
  - HTML/script tag stripping
  - Length and structure validation
"""
from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.ai.output_validation")


# ---------------------------------------------------------------------------
# Dangerous Output Patterns
# ---------------------------------------------------------------------------
DANGEROUS_REMEDIATION_COMMANDS = [
    "rm -rf /",
    "rm -rf /etc",
    "rm -rf /var",
    "rm -rf /*",
    "dd if=/dev/zero",
    "dd if=/dev/urandom",
    "format c:",
    "del /f /s /q",
    "shutdown -h now",
    "shutdown /s",
    "reboot",
    "DROP DATABASE",
    "DROP TABLE",
    "TRUNCATE TABLE",
    "DELETE FROM * WHERE 1=1",
    ":(){:|:&};:",    # Fork bomb
    "mkfs.",
    "fdisk",
    "passwd root",
    "chmod 777 /",
    "chown -R nobody /",
]

DANGEROUS_OUTPUT_PATTERNS = [
    r'<script[^>]*>',
    r'javascript:',
    r'onclick\s*=',
    r'onerror\s*=',
    r'<iframe',
    r'<object',
    r'eval\s*\(',
    r'exec\s*\(',
    r'__import__\s*\(',
    r'subprocess\.',
    r'os\.system\s*\(',
    r'os\.popen\s*\(',
]


class LLMOutputValidator:
    """Validate and sanitize all LLM-generated content."""

    def validate_incident_summary(self, summary: str) -> tuple[bool, str]:
        """Validate an AI-generated incident summary.
        
        Returns (is_valid, reason).
        """
        if not summary:
            return False, "Summary is empty"

        if len(summary) < 20:
            return False, f"Summary too short ({len(summary)} chars, minimum 20)"

        if len(summary) > 10000:
            return False, f"Summary too long ({len(summary)} chars, maximum 10000)"

        # Check for dangerous patterns
        for pattern in DANGEROUS_OUTPUT_PATTERNS:
            if re.search(pattern, summary, re.IGNORECASE):
                logger.warning(f"Dangerous pattern in summary: {pattern}")
                return False, f"Dangerous pattern detected: {pattern}"

        return True, "Valid"

    def validate_remediation_steps(self, steps: List[str]) -> tuple[bool, str]:
        """Validate AI-generated remediation steps."""
        if not steps:
            return False, "No remediation steps provided"

        if len(steps) > 20:
            return False, f"Too many steps ({len(steps)}, max 20)"

        for i, step in enumerate(steps):
            if len(step) < 10:
                return False, f"Step {i+1} too short"

            if len(step) > 2000:
                return False, f"Step {i+1} too long"

            # Check for dangerous commands
            if self._is_dangerous_command(step):
                return False, f"Step {i+1} contains a dangerous command"

            # Check for code injection
            for pattern in DANGEROUS_OUTPUT_PATTERNS:
                if re.search(pattern, step, re.IGNORECASE):
                    return False, f"Step {i+1} contains dangerous pattern: {pattern}"

        return True, "Valid"

    def validate_detection_rule(self, rule: str, rule_type: str = "sigma") -> tuple[bool, str]:
        """Validate AI-generated detection rules (Sigma/YARA)."""
        if not rule:
            return False, "Rule is empty"

        if len(rule) > 50000:
            return False, "Rule exceeds maximum size"

        if rule_type == "sigma":
            # Basic Sigma YAML structure validation
            required_fields = ["title:", "logsource:", "detection:"]
            for field in required_fields:
                if field not in rule:
                    return False, f"Missing required Sigma field: {field}"

        elif rule_type == "yara":
            # Basic YARA structure validation
            if "rule " not in rule:
                return False, "Missing 'rule' keyword in YARA rule"
            if "condition:" not in rule:
                return False, "Missing 'condition:' in YARA rule"

        return True, "Valid"

    def validate_confidence_score(self, score: float) -> tuple[bool, str]:
        """Validate that a confidence score is within bounds."""
        if not isinstance(score, (int, float)):
            return False, "Score must be numeric"
        if score < 0.0 or score > 1.0:
            return False, f"Score {score} out of range [0.0, 1.0]"
        return True, "Valid"

    def _is_dangerous_command(self, text: str) -> bool:
        """Check if text contains dangerous system commands."""
        lower_text = text.lower()
        for cmd in DANGEROUS_REMEDIATION_COMMANDS:
            if cmd.lower() in lower_text:
                logger.warning(f"Dangerous command detected in output: {cmd}")
                return True
        return False

    def sanitize_summary(self, summary: str) -> str:
        """Remove/escape dangerous content from a summary."""
        # Remove HTML tags
        cleaned = re.sub(r'<[^>]+>', '', summary)

        # Escape special characters
        cleaned = (
            cleaned
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;')
        )

        return cleaned.strip()

    def sanitize_remediation_steps(self, steps: List[str]) -> List[str]:
        """Sanitize remediation steps, removing dangerous commands."""
        sanitized = []
        for step in steps:
            # Remove dangerous commands
            clean_step = step
            for cmd in DANGEROUS_REMEDIATION_COMMANDS:
                clean_step = clean_step.replace(cmd, "[REDACTED_UNSAFE_COMMAND]")

            # Remove HTML/script tags
            clean_step = re.sub(r'<[^>]+>', '', clean_step)
            sanitized.append(clean_step.strip())

        return sanitized

    def validate_and_sanitize(self, content: str, content_type: str = "summary") -> tuple[str, bool, str]:
        """Validate and sanitize content. Returns (sanitized_content, is_valid, reason)."""
        if content_type == "summary":
            is_valid, reason = self.validate_incident_summary(content)
            sanitized = self.sanitize_summary(content)
        else:
            is_valid, reason = True, "Generic content"
            sanitized = self.sanitize_summary(content)

        return sanitized, is_valid, reason


# Global validator instance
output_validator = LLMOutputValidator()
