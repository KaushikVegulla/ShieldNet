from collections import Counter

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from . import anomaly_scoring, hybrid, ml_scoring, models, schemas, scoring
from .db import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ShieldNet Backend", version="0.1.0")

# Dashboard (Vercel / localhost) calls this API from a browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _store_request(db: Session, payload: schemas.RequestIn) -> models.RequestLog:
    log = models.RequestLog(
        ip=payload.ip,
        method=payload.method.upper(),
        uri=payload.uri,
        headers=payload.headers,
        body_sample=(payload.body or "")[:2000] or None,
        user_agent=payload.headers.get("user-agent") or payload.headers.get("User-Agent"),
        modsec_rule_ids=payload.modsec_rule_ids,
        modsec_score=payload.modsec_score,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


@app.get("/health")
def health():
    return {"status": "ok", "service": "shieldnet-backend"}


@app.post("/ingest", response_model=schemas.RequestLogOut, status_code=201)
def ingest(payload: schemas.RequestIn, db: Session = Depends(get_db)):
    """Log a request (e.g. from the ModSecurity audit pipeline). No scoring."""
    return _store_request(db, payload)


@app.post("/analyze", response_model=schemas.AnalyzeOut)
def analyze(payload: schemas.RequestIn, db: Session = Depends(get_db)):
    """Log a request, score it, store a detection, return the decision.

    All three signals (rules, ML, anomaly) feed the hybrid engine
    (app/hybrid.py). Any signal whose model isn't loaded is null and the
    hybrid weights renormalise over the rest.
    """
    log = _store_request(db, payload)
    result = scoring.rule_score_for(payload.uri, payload.body, payload.modsec_score)
    ml = ml_scoring.score(payload.method, payload.uri, payload.body, payload.headers)
    anomaly = anomaly_scoring.score(payload.method, payload.uri, payload.body, payload.headers)
    risk = hybrid.combine(result.rule_score, ml, anomaly)
    decision = hybrid.decide(risk)
    attack_type = result.attack_type
    if attack_type is None and decision != "allow" and anomaly is not None and anomaly >= 75:
        attack_type = "anomaly"
    detection = models.Detection(
        request_id=log.id,
        rule_score=result.rule_score,
        ml_score=ml,
        anomaly_score=anomaly,
        risk_score=risk,
        decision=decision,
        attack_type=attack_type,
        model_version=ml_scoring.model_version(),
    )
    db.add(detection)
    db.commit()
    db.refresh(detection)
    return schemas.AnalyzeOut(
        request_id=log.id,
        rule_score=detection.rule_score,
        ml_score=detection.ml_score,
        anomaly_score=detection.anomaly_score,
        risk_score=detection.risk_score,
        decision=detection.decision,
        attack_type=detection.attack_type,
        matched_patterns=result.matched_patterns,
    )


@app.get("/logs", response_model=list[schemas.RequestLogOut])
def list_logs(limit: int = 50, db: Session = Depends(get_db)):
    return (
        db.query(models.RequestLog)
        .order_by(models.RequestLog.id.desc())
        .limit(min(limit, 500))
        .all()
    )


@app.get("/detections", response_model=list[schemas.DetectionOut])
def list_detections(limit: int = 50, db: Session = Depends(get_db)):
    return (
        db.query(models.Detection)
        .order_by(models.Detection.id.desc())
        .limit(min(limit, 500))
        .all()
    )


@app.get("/model-metrics")
def model_metrics():
    """Training metrics for the dashboard, read from the models directory.

    Looks next to MODEL_PATH / ANOMALY_MODEL_PATH for metrics.json and
    anomaly_metrics.json (written by ml/train.py / ml/train_anomaly.py).
    Returns nulls when no metrics files are present.
    """
    import json
    import os

    def _read(env_var: str, filename: str):
        path = os.environ.get(env_var, "")
        if not path:
            return None
        candidate = os.path.join(os.path.dirname(path), filename)
        try:
            with open(candidate, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    return {
        "classifier": _read("MODEL_PATH", "metrics.json"),
        "anomaly": _read("ANOMALY_MODEL_PATH", "anomaly_metrics.json"),
    }


@app.get("/stats", response_model=schemas.StatsOut)
def stats(db: Session = Depends(get_db)):
    detections = db.query(models.Detection).all()
    return schemas.StatsOut(
        total_requests=db.query(models.RequestLog).count(),
        total_detections=len(detections),
        by_decision=dict(Counter(d.decision for d in detections)),
        by_attack_type=dict(Counter(d.attack_type for d in detections if d.attack_type)),
    )
