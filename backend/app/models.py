from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    ip = Column(String(64), nullable=True)
    method = Column(String(16))
    uri = Column(Text)
    headers = Column(JSON, default=dict)
    body_sample = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)
    modsec_rule_ids = Column(JSON, default=list)
    modsec_score = Column(Float, nullable=True)

    detection = relationship("Detection", back_populates="request", uselist=False)


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("request_logs.id"), index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    rule_score = Column(Float, default=0.0)
    ml_score = Column(Float, nullable=True)       # Phase 3
    anomaly_score = Column(Float, nullable=True)  # Phase 4
    risk_score = Column(Float, default=0.0)
    decision = Column(String(16), index=True)  # allow | monitor | block
    attack_type = Column(String(32), nullable=True)
    model_version = Column(String(32), default="baseline-rules-v1")

    request = relationship("RequestLog", back_populates="detection")


class User(Base):
    """Console user. Only the Argon2id password hash is stored, never the
    password itself."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=True)
    password_hash = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RefreshToken(Base):
    """A hashed refresh token. The raw token lives only in the user's
    httpOnly cookie; storing the SHA-256 hash lets us rotate and revoke
    sessions (logout, reuse detection) server-side."""

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String(64), index=True)
    expires_at = Column(DateTime(timezone=True))
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    user = relationship("User")
