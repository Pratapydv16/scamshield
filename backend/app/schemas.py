from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


ScanType = Literal["url", "email", "sms", "payment"]


class ScanRequest(BaseModel):
    scan_type: ScanType
    input: str = Field(min_length=1, max_length=10_000)
    share_with_google: bool = False

    @field_validator("input")
    @classmethod
    def sanitize_input(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("input must not be empty")
        if any(ord(char) < 32 and char not in "\r\n\t" for char in clean):
            raise ValueError("input contains unsupported control characters")
        return clean


class FindingResponse(BaseModel):
    code: str
    title: str
    detail: str
    severity: str


class ThreatIntelligenceResponse(BaseModel):
    provider: Literal["google_web_risk"] | None = None
    status: Literal["not_checked", "not_configured", "skipped", "matched", "clear", "error"]
    threat_types: list[str] = Field(default_factory=list)
    message: str


class ScanResponse(BaseModel):
    id: str
    scan_type: ScanType
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "elevated", "high"]
    explanation: str
    findings: list[FindingResponse]
    recommendations: list[str]
    scanned_at: datetime
    detection_mode: Literal["heuristic", "hybrid"]
    threat_intelligence: ThreatIntelligenceResponse | None = None


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    plan: str
    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class APIKeyResponse(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime


class APIKeyRequest(BaseModel):
    name: str = Field(default="Integration", min_length=1, max_length=80)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("name must not be empty")
        return clean


class APIKeyCreated(APIKeyResponse):
    key: str
