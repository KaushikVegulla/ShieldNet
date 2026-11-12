from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str


class RequestIn(BaseModel):
    """A single HTTP request to log and/or analyze."""

    ip: Optional[str] = None
    method: str = "GET"
    uri: str
    headers: dict[str, Any] = Field(default_factory=dict)
    body: Optional[str] = None
    modsec_rule_ids: list[str] = Field(default_factory=list)
    modsec_score: Optional[float] = None


class RequestLogOut(BaseModel):
    id: int
    created_at: datetime
    ip: Optional[str]
    method: str
    uri: str
    user_agent: Optional[str]
    modsec_rule_ids: list[str]
    modsec_score: Optional[float]

    model_config = {"from_attributes": True}


class DetectionOut(BaseModel):
    id: int
    request_id: int
    created_at: datetime
    rule_score: float
    ml_score: Optional[float]
    anomaly_score: Optional[float]
    risk_score: float
    decision: str
    attack_type: Optional[str]
    model_version: str

    model_config = {"from_attributes": True}


class AnalyzeOut(BaseModel):
    request_id: int
    rule_score: float
    ml_score: Optional[float]
    anomaly_score: Optional[float]
    risk_score: float
    decision: str  # allow | monitor | block
    attack_type: Optional[str]
    matched_patterns: list[str]


class StatsOut(BaseModel):
    total_requests: int
    total_detections: int
    by_decision: dict[str, int]
    by_attack_type: dict[str, int]
