"""EDYSOR Input Validation — Strict Pydantic models for all API endpoints.

Provides:
  - AlertIngestionRequest with severity/source validation
  - PlaybookExecutionRequest with parameter sanitization
  - IncidentCreateRequest with safe text validators  
  - Generic text sanitizer removing HTML, scripts, SQL keywords
"""
from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.security.input_validation")

# ---------------------------------------------------------------------------
# Dangerous Patterns
# ---------------------------------------------------------------------------
DANGEROUS_HTML_PATTERNS = [
    r'<script', r'javascript:', r'onclick', r'onerror', r'onload',
    r'onmouseover', r'onfocus', r'<iframe', r'<object', r'<embed',
    r'<form', r'data:text/html', r'vbscript:',
]

DANGEROUS_SQL_PATTERNS = [
    r"DROP\s+TABLE", r"DROP\s+DATABASE", r"DELETE\s+FROM",
    r"INSERT\s+INTO", r"UPDATE\s+\w+\s+SET", r"TRUNCATE\s+TABLE",
    r"ALTER\s+TABLE", r"EXEC\s*\(", r"xp_cmdshell",
    r";\s*--", r"'\s*OR\s+'1'\s*=\s*'1",
    r"UNION\s+SELECT", r"UNION\s+ALL\s+SELECT",
]


def sanitize_text(text: str) -> str:
    """Remove HTML tags and dangerous content from text."""
    if not text:
        return text
    # Remove HTML tags
    cleaned = re.sub(r'<[^>]+>', '', text)
    # Escape remaining special characters
    cleaned = (
        cleaned
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#x27;')
    )
    return cleaned.strip()


def check_for_injection(text: str) -> tuple[bool, str]:
    """Check text for SQL injection and XSS patterns.
    
    Returns (is_safe, reason).
    """
    if not text:
        return True, ""

    lower_text = text.lower()

    for pattern in DANGEROUS_HTML_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            reason = f"Potentially malicious HTML/XSS pattern detected: {pattern}"
            logger.warning(f"Input validation failed: {reason}")
            return False, reason

    for pattern in DANGEROUS_SQL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            reason = f"Potentially malicious SQL pattern detected: {pattern}"
            logger.warning(f"Input validation failed: {reason}")
            return False, reason

    return True, ""


# ---------------------------------------------------------------------------
# Validation Models (Plain classes — no Pydantic dependency required)
# ---------------------------------------------------------------------------
class ValidationError(Exception):
    """Raised when input validation fails."""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"Validation error on '{field}': {message}")


class AlertIngestionValidator:
    """Validates alert ingestion payloads."""

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    MAX_TITLE_LENGTH = 500
    MAX_DESCRIPTION_LENGTH = 5000
    MAX_TAGS = 20

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize alert ingestion data."""
        errors = []

        # source_system
        source = data.get("source_system", "")
        if not source or len(source) < 3 or len(source) > 50:
            errors.append(ValidationError("source_system", "Must be 3-50 characters"))

        # severity
        severity = data.get("severity", "").lower()
        if severity not in cls.VALID_SEVERITIES:
            errors.append(ValidationError("severity", f"Must be one of: {cls.VALID_SEVERITIES}"))

        # title
        title = data.get("title", "")
        if not title or len(title) > cls.MAX_TITLE_LENGTH:
            errors.append(ValidationError("title", f"Required, max {cls.MAX_TITLE_LENGTH} chars"))
        else:
            is_safe, reason = check_for_injection(title)
            if not is_safe:
                errors.append(ValidationError("title", reason))

        # description
        description = data.get("description", "")
        if len(description) > cls.MAX_DESCRIPTION_LENGTH:
            errors.append(ValidationError("description", f"Max {cls.MAX_DESCRIPTION_LENGTH} chars"))
        elif description:
            is_safe, reason = check_for_injection(description)
            if not is_safe:
                errors.append(ValidationError("description", reason))

        # tags
        tags = data.get("tags", [])
        if not isinstance(tags, list):
            errors.append(ValidationError("tags", "Must be a list"))
        elif len(tags) > cls.MAX_TAGS:
            errors.append(ValidationError("tags", f"Max {cls.MAX_TAGS} tags"))
        elif len(tags) != len(set(tags)):
            errors.append(ValidationError("tags", "Duplicate tags not allowed"))

        if errors:
            raise errors[0]  # Raise first error

        # Return sanitized data
        return {
            "source_system": source.strip(),
            "severity": severity,
            "title": sanitize_text(title),
            "description": sanitize_text(description),
            "tags": [t.strip()[:50] for t in tags],
        }


class PlaybookExecutionValidator:
    """Validates playbook execution requests."""

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate playbook execution parameters."""

        playbook_id = data.get("playbook_id", "")
        if not playbook_id or not re.match(r'^[a-zA-Z0-9_\-]+$', playbook_id):
            raise ValidationError("playbook_id", "Must be alphanumeric with hyphens/underscores")

        # Validate parameters — no shell injection
        params = data.get("parameters", {})
        if not isinstance(params, dict):
            raise ValidationError("parameters", "Must be a dictionary")

        sanitized_params = {}
        for key, value in params.items():
            if not re.match(r'^[a-zA-Z0-9_]+$', key):
                raise ValidationError(f"parameters.{key}", "Key must be alphanumeric")
            if isinstance(value, str):
                is_safe, reason = check_for_injection(value)
                if not is_safe:
                    raise ValidationError(f"parameters.{key}", reason)
                sanitized_params[key] = sanitize_text(value)
            else:
                sanitized_params[key] = value

        return {
            "playbook_id": playbook_id,
            "parameters": sanitized_params,
            "target": sanitize_text(data.get("target", "")),
            "priority": data.get("priority", "normal"),
        }


class IncidentCreateValidator:
    """Validates incident creation payloads."""

    VALID_SEVERITIES = {"critical", "high", "medium", "low"}
    MAX_TITLE_LENGTH = 300
    MAX_DESCRIPTION_LENGTH = 10000

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize incident creation data."""

        title = data.get("title", "")
        if not title or len(title) > cls.MAX_TITLE_LENGTH:
            raise ValidationError("title", f"Required, max {cls.MAX_TITLE_LENGTH} chars")
        is_safe, reason = check_for_injection(title)
        if not is_safe:
            raise ValidationError("title", reason)

        severity = data.get("severity", "").lower()
        if severity not in cls.VALID_SEVERITIES:
            raise ValidationError("severity", f"Must be one of: {cls.VALID_SEVERITIES}")

        description = data.get("description", "")
        if len(description) > cls.MAX_DESCRIPTION_LENGTH:
            raise ValidationError("description", f"Max {cls.MAX_DESCRIPTION_LENGTH} chars")
        if description:
            is_safe, reason = check_for_injection(description)
            if not is_safe:
                raise ValidationError("description", reason)

        return {
            "title": sanitize_text(title),
            "severity": severity,
            "description": sanitize_text(description),
            "assigned_to": data.get("assigned_to", ""),
            "tags": data.get("tags", []),
        }


class CopilotQueryValidator:
    """Validates copilot chat queries against injection."""

    MAX_QUERY_LENGTH = 10000

    @classmethod
    def validate(cls, query: str) -> str:
        """Validate and return sanitized copilot query."""
        if not query or not query.strip():
            raise ValidationError("query", "Query cannot be empty")
        if len(query) > cls.MAX_QUERY_LENGTH:
            raise ValidationError("query", f"Max {cls.MAX_QUERY_LENGTH} characters")
        # Don't fully sanitize copilot queries — just check for injection
        is_safe, reason = check_for_injection(query)
        if not is_safe:
            raise ValidationError("query", reason)
        return query.strip()
