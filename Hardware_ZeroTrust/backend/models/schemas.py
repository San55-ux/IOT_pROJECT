"""
Pydantic Schemas for Zero-Trust Hardware-Bound Authentication Gateway
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Any


class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(..., description="Unique Hardware Device ID (e.g. ESP32-001)")
    mac_address: str = Field(..., description="eFuse or Wi-Fi MAC Address")
    chip_model: Optional[str] = "ESP32"
    chip_revision: Optional[int] = 1
    public_key: str = Field(..., description="Schnorr Public Key Y in hex format")
    helper_data: Optional[str] = Field(None, description="PUF stable bit mask (helper data)")


class DeviceRegisterResponse(BaseModel):
    success: bool
    message: str
    device_id: str
    trust_status: str


class AuthChallengeRequest(BaseModel):
    device_id: str = Field(..., description="Registered Device ID requesting authentication")
    commitment: str = Field(..., description="Schnorr Commitment Point R = k*G in hex")


class AuthChallengeResponse(BaseModel):
    session_id: str
    device_id: str
    challenge: str = Field(..., description="Ephemeral 256-bit challenge scalar c in hex")
    expires_in_seconds: int


class AuthVerifyRequest(BaseModel):
    session_id: str = Field(..., description="Active session ID received from /auth/challenge")
    device_id: str = Field(..., description="Device ID submitting proof")
    response: str = Field(..., description="Schnorr response scalar s = (k + c*x) mod q in hex")


class AuthVerifyResponse(BaseModel):
    authenticated: bool
    trust_status: str
    message: str
    relay_status: str
    latency_ms: float


class RelayOverrideRequest(BaseModel):
    status: str = Field(..., pattern="^(LOCKED|UNLOCKED)$")
    duration_seconds: Optional[int] = 5
    reason: Optional[str] = "MANUAL_DASHBOARD_OVERRIDE"


class LogItem(BaseModel):
    id: int
    device_id: str
    timestamp: str
    result: str
    latency_ms: float
    failure_reason: Optional[str] = None
    client_ip: Optional[str] = None


class AlertItem(BaseModel):
    id: int
    device_id: Optional[str]
    alert_type: str
    description: str
    timestamp: str
    severity: str
    resolved: int
