"""Pydantic models with input validation hardening."""
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
import re

class AlertInput(BaseModel):
    """Hardened Alert Input model."""
    title: str = Field(..., max_length=200)
    evidence: dict
    confidence_score: float = Field(default=80.0, ge=0.0, le=100.0)

class TelemetryLog(BaseModel):
    """Validated telemetry log for ingestion."""
    timestamp: Optional[datetime] = None
    event_type: str = Field(..., max_length=50)
    source_ip: str = Field(..., max_length=45)
    user_id: Optional[str] = Field(None, max_length=100)
    status: str = Field(..., max_length=20)
    device_id: Optional[str] = Field(None, max_length=200)
    user_agent: Optional[str] = Field(None, max_length=500)
    endpoint: Optional[str] = Field(None, max_length=500)
    method: Optional[str] = Field(None, max_length=10)
    headers: Optional[dict] = None

    @field_validator('event_type')
    @classmethod
    def validate_event_type(cls, v):
        allowed = {'login', 'otp_request', 'page_view', 'api_call',
                    'coupon_apply', 'order', 'logout', 'password_reset',
                    'signup', 'profile_update'}
        if v not in allowed:
            raise ValueError(f"event_type must be one of: {allowed}")
        return v

    @field_validator('source_ip')
    @classmethod
    def validate_ip(cls, v):
        # Basic IP validation (IPv4 + IPv6)
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        if not (re.match(ipv4_pattern, v) or re.match(ipv6_pattern, v)):
            raise ValueError("Invalid IP address format")
        return v

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        allowed = {'success', 'failed', 'error', 'blocked', 'pending'}
        if v not in allowed:
            raise ValueError(f"status must be one of: {allowed}")
        return v

    @field_validator('method')
    @classmethod
    def validate_method(cls, v):
        if v is None:
            return v
        allowed = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'}
        if v.upper() not in allowed:
            raise ValueError(f"method must be one of: {allowed}")
        return v.upper()

from typing import Dict, Any
import ipaddress

class LogEntry(BaseModel):
    """Validated log entry with security-first design"""
    
    timestamp: datetime = Field(..., description="ISO 8601 timestamp of event")
    user_id: str = Field(..., min_length=1, max_length=128, description="Unique user identifier")
    event_type: str = Field(..., pattern="^[A-Z_]{3,32}$", description="Event category (e.g., LOGIN_SUCCESS)")
    source_ip: str = Field(..., description="Source IP address")
    target_ip: Optional[str] = Field(None, description="Target/destination IP")
    raw_data: str = Field(..., max_length=50000, description="Full log payload")
    severity: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARN|ERROR|CRITICAL)$")
    device_id: Optional[str] = Field(None, max_length=256, description="Device fingerprint identifier")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, max_items=20, description="Additional context")
    
    @field_validator('user_id')
    @classmethod
    def sanitize_user_id(cls, v):
        v = v.replace('\x00', '').replace('\n', '').replace('\t', '')
        return v.strip()[:128]
    
    @field_validator('raw_data')
    @classmethod
    def sanitize_raw_data(cls, v):
        dangerous_patterns = [
            r'<\|im_(start|end)\|>',
            r'(?i)^system\s*:',
            r'(?i)^assistant\s*:',
            r'(?i)^user\s*:',
            r'"""',
            r"'''",
        ]
        for pattern in dangerous_patterns:
            v = re.sub(pattern, '[REDACTED]', v, flags=re.MULTILINE)
        return v
    
    @field_validator('source_ip')
    @classmethod
    def validate_source_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v
    
    @field_validator('target_ip')
    @classmethod
    def validate_target_ip(cls, v):
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v
    
    @field_validator('metadata')
    @classmethod
    def validate_metadata(cls, v):
        if not v:
            return {}
        for key, value in v.items():
            if isinstance(value, str) and len(value) > 5000:
                raise ValueError(f"Metadata field '{key}' exceeds 5000 chars")
        return v

class BatchLogIngestion(BaseModel):
    """Batch multiple logs in single request"""
    logs: list[LogEntry] = Field(..., max_items=1000)
    
    @field_validator('logs')
    @classmethod
    def validate_batch_size(cls, v):
        if len(v) > 1000:
            raise ValueError("Max 1000 logs per batch")
        return v



class ChatRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=4, max_length=100)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)
    role: str = Field(default="analyst", max_length=20)


class VerdictRequest(BaseModel):
    verdict: str = Field(..., max_length=30)
    notes: Optional[str] = Field(None, max_length=1000)

    @field_validator('verdict')
    @classmethod
    def validate_verdict(cls, v):
        allowed = {'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', 'PENDING'}
        if v not in allowed:
            raise ValueError(f"verdict must be one of: {allowed}")
        return v


class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None

class ApprovalRequest(BaseModel):
    notes: Optional[str] = Field(None, max_length=1000)


class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class VulnerabilityRecord(BaseModel):
    ip_address: str = Field(..., max_length=45)
    cve_id: Optional[str] = Field(None, max_length=30)
    severity: str = Field(..., max_length=20)
    title: str = Field(..., max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    tool_source: Optional[str] = Field(None, max_length=50)

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        allowed = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of: {allowed}")
        return v.upper()


class VulnerabilityUpload(BaseModel):
    records: list[VulnerabilityRecord]


class DevSecOpsAlert(BaseModel):
    repo_name: str = Field(..., max_length=100)
    tool_name: str = Field(..., max_length=50)
    cve_id: Optional[str] = Field(None, max_length=30)
    severity: str = Field(..., max_length=20)
    description: Optional[str] = Field(None, max_length=1000)
    commit_hash: Optional[str] = Field(None, max_length=64)

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        allowed = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of: {allowed}")
        return v.upper()


class AssetRecord(BaseModel):
    ip_address: str = Field(..., max_length=45)
    hostname: str = Field(..., max_length=100)
    owner: Optional[str] = Field(None, max_length=100)
    os: Optional[str] = Field(None, max_length=50)
    criticality: str = Field(..., max_length=20)

    @field_validator('criticality')
    @classmethod
    def validate_criticality(cls, v):
        allowed = {'HIGH', 'MEDIUM', 'LOW'}
        if v.upper() not in allowed:
            raise ValueError(f"criticality must be one of: {allowed}")
        return v.upper()


class AssetInventoryUpload(BaseModel):
    assets: list[AssetRecord]


class IDSAlertLog(BaseModel):
    source_ip: str = Field(..., max_length=45)
    target_ip: str = Field(..., max_length=45)
    signature: str = Field(..., max_length=200)
    severity: str = Field(..., max_length=20)
    protocol: Optional[str] = Field(None, max_length=10)
    payload_hex: Optional[str] = Field(None, max_length=1000)

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        allowed = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of: {allowed}")
        return v.upper()


class VirtualPatchRecord(BaseModel):
    rule_name: str = Field(..., max_length=100)
    target_endpoint: str = Field(..., max_length=500)
    pattern_regex: str = Field(..., max_length=1000)
    action: str = Field(..., max_length=20)

    @field_validator('action')
    @classmethod
    def validate_action(cls, v):
        allowed = {'BLOCK', 'LOG'}
        if v.upper() not in allowed:
            raise ValueError(f"action must be one of: {allowed}")
        return v.upper()


class VirtualPatchUpload(BaseModel):
    patches: list[VirtualPatchRecord]


class KnowledgeDocument(BaseModel):
    title: str = Field(..., max_length=200)
    content: str = Field(..., min_length=1)
    source: str = Field(default="playbook", max_length=100)


class KnowledgeUpload(BaseModel):
    documents: list[KnowledgeDocument]

