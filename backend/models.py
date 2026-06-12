from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class TelemetryLog(BaseModel):
    timestamp: Optional[datetime] = None
    event_type: str  # "login", "otp_request", "page_view", "api_call", "coupon_apply", "order"
    source_ip: str
    user_id: Optional[str] = None
    status: str  # "success", "failed"
    device_id: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
