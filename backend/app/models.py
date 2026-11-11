from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Integer, String, Text
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
