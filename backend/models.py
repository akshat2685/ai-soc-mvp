"""Pydantic models with input validation hardening."""
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
import re


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
