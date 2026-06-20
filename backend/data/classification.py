"""EDYSOR Data Classification & Handling Policies.

Provides:
  - Four-tier data classification (Public, Internal, Confidential, Restricted)
  - Policy enforcement for encryption, retention, access logging, masking
  - Classification-aware data handlers
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.data.classification")


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# ---------------------------------------------------------------------------
# Data Handling Policies
# ---------------------------------------------------------------------------
DATA_HANDLING_POLICIES: Dict[DataClassification, Dict[str, Any]] = {
    DataClassification.PUBLIC: {
        "encryption_at_rest": False,
        "encryption_in_transit": True,
        "retention_days": 365,
        "access_log": False,
        "requires_approval": False,
        "mask_in_logs": False,
        "audit_all_access": False,
        "description": "Non-sensitive data — publicly shareable",
    },
    DataClassification.INTERNAL: {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "retention_days": 180,
        "access_log": True,
        "requires_approval": False,
        "mask_in_logs": False,
        "audit_all_access": False,
        "description": "Internal use only — not for external distribution",
    },
    DataClassification.CONFIDENTIAL: {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "retention_days": 90,
        "access_log": True,
        "requires_approval": True,
        "mask_in_logs": True,
        "audit_all_access": True,
        "description": "Sensitive data — restricted distribution, requires approval",
    },
    DataClassification.RESTRICTED: {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "retention_days": 30,
        "access_log": True,
        "requires_approval": True,
        "mask_in_logs": True,
        "audit_all_access": True,
        "pii_handling": True,
        "description": "Highly sensitive — PII, credentials, secrets",
    },
}


# ---------------------------------------------------------------------------
# Field Classification Registry
# ---------------------------------------------------------------------------
FIELD_CLASSIFICATIONS: Dict[str, DataClassification] = {
    # Alert fields
    "alert_id": DataClassification.INTERNAL,
    "alert_title": DataClassification.INTERNAL,
    "alert_description": DataClassification.INTERNAL,
    "source_ip": DataClassification.CONFIDENTIAL,
    "destination_ip": DataClassification.CONFIDENTIAL,
    "affected_user": DataClassification.RESTRICTED,
    "affected_email": DataClassification.RESTRICTED,

    # Incident fields
    "incident_id": DataClassification.INTERNAL,
    "incident_summary": DataClassification.CONFIDENTIAL,
    "affected_assets": DataClassification.CONFIDENTIAL,
    "remediation_steps": DataClassification.CONFIDENTIAL,

    # Credential fields
    "api_key": DataClassification.RESTRICTED,
    "password_hash": DataClassification.RESTRICTED,
    "access_token": DataClassification.RESTRICTED,
    "refresh_token": DataClassification.RESTRICTED,
    "client_secret": DataClassification.RESTRICTED,

    # System fields
    "hostname": DataClassification.INTERNAL,
    "os_version": DataClassification.PUBLIC,
    "detection_rule": DataClassification.INTERNAL,
}


def get_policy(classification: DataClassification) -> Dict[str, Any]:
    """Get the handling policy for a data classification level."""
    return DATA_HANDLING_POLICIES.get(classification, DATA_HANDLING_POLICIES[DataClassification.INTERNAL])


def get_field_classification(field_name: str) -> DataClassification:
    """Get classification for a known field name, defaulting to INTERNAL."""
    return FIELD_CLASSIFICATIONS.get(field_name, DataClassification.INTERNAL)


def classify_data(data: Dict[str, Any]) -> Dict[str, DataClassification]:
    """Classify all fields in a data dictionary."""
    return {
        key: get_field_classification(key)
        for key in data.keys()
    }


def mask_field(value: str, classification: DataClassification) -> str:
    """Mask a field value based on its classification for log output."""
    policy = get_policy(classification)
    if not policy.get("mask_in_logs", False):
        return value
    if not value:
        return value
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def should_encrypt(field_name: str) -> bool:
    """Check if a field should be encrypted at rest."""
    classification = get_field_classification(field_name)
    policy = get_policy(classification)
    return policy.get("encryption_at_rest", False)


def get_retention_days(field_name: str) -> int:
    """Get retention period in days for a field."""
    classification = get_field_classification(field_name)
    policy = get_policy(classification)
    return policy.get("retention_days", 180)
