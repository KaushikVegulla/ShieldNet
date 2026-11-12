from collections import Counter

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from . import anomaly_scoring, auth, hybrid, ml_scoring, models, schemas, scoring
from .config import settings
from .db import Base, SessionLocal, engine, get_db

Base.metadata.create_all(bind=engine)
auth.migrate_users_table(engine)

with SessionLocal() as _seed_db:
    auth.ensure_seed_user(_seed_db)

app = FastAPI(title="ShieldNet Backend", version="0.1.0")

# Dashboard (Vercel / localhost) calls this API from a browser. Credentialed
# requests (refresh cookie) require explicit origins — "*" is not allowed
# with credentials — so origins come from CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
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


# --- Auth: JWT access token + rotating httpOnly refresh cookie ---

def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        auth.REFRESH_COOKIE,
        raw_token,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        max_age=settings.refresh_token_days * 86400,
        path=auth.REFRESH_COOKIE_PATH,
    )


@app.post("/auth/login", response_model=schemas.TokenOut)
def login(payload: schemas.LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    auth.check_login_rate_limit(email, client_ip)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None or not auth.verify_password(user.password_hash, payload.password):
        auth.record_login_failure(email, client_ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    auth.clear_login_failures(email, client_ip)
    _set_refresh_cookie(response, auth.create_refresh_token(db, user))
    return schemas.TokenOut(access_token=auth.create_access_token(user.email), email=user.email, name=user.name)


@app.post("/auth/register", response_model=schemas.TokenOut, status_code=201)
def register(payload: schemas.RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Create an account and sign the new user in immediately."""
    email = payload.email.strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    auth.check_login_rate_limit(email, client_ip)
    if "@" not in email or "." not in email.split("@")[-1]:
        auth.record_login_failure(email, client_ip)
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if len(payload.password) < 8:
        auth.record_login_failure(email, client_ip)
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if db.query(models.User).filter(models.User.email == email).first() is not None:
        auth.record_login_failure(email, client_ip)
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = models.User(
        email=email,
        name=(payload.name or "").strip() or None,
        password_hash=auth.hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _set_refresh_cookie(response, auth.create_refresh_token(db, user))
    return schemas.TokenOut(access_token=auth.create_access_token(user.email), email=user.email, name=user.name)


@app.post("/auth/refresh", response_model=schemas.TokenOut)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    record = auth.verify_refresh_token(db, request.cookies.get(auth.REFRESH_COOKIE, ""))
    if record is None:
        raise HTTPException(status_code=401, detail="No valid refresh session")
    _set_refresh_cookie(response, auth.rotate_refresh_token(db, record))
    return schemas.TokenOut(access_token=auth.create_access_token(record.user.email), email=record.user.email, name=record.user.name)


@app.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    auth.revoke_refresh_token(db, request.cookies.get(auth.REFRESH_COOKIE, ""))
    response.delete_cookie(auth.REFRESH_COOKIE, path=auth.REFRESH_COOKIE_PATH)
    return {"ok": True}


@app.get("/auth/me")
def me(user: models.User = Depends(auth.get_current_user)):
    return {"email": user.email, "name": user.name}


@app.post("/ingest", response_model=schemas.RequestLogOut, status_code=201, dependencies=[Depends(auth.require_write_access)])
def ingest(payload: schemas.RequestIn, db: Session = Depends(get_db)):
    """Log a request (e.g. from the ModSecurity audit pipeline). No scoring."""
    return _store_request(db, payload)


@app.post("/analyze", response_model=schemas.AnalyzeOut, dependencies=[Depends(auth.require_write_access)])
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
def list_logs(limit: int = 50, db: Session = Depends(get_db), _user: models.User = Depends(auth.get_current_user)):
    return (
        db.query(models.RequestLog)
        .order_by(models.RequestLog.id.desc())
        .limit(min(limit, 500))
        .all()
    )


@app.get("/detections", response_model=list[schemas.DetectionOut])
def list_detections(limit: int = 50, db: Session = Depends(get_db), _user: models.User = Depends(auth.get_current_user)):
    return (
        db.query(models.Detection)
        .order_by(models.Detection.id.desc())
        .limit(min(limit, 500))
        .all()
    )


@app.get("/model-metrics")
def model_metrics(_user: models.User = Depends(auth.get_current_user)):
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
def stats(db: Session = Depends(get_db), _user: models.User = Depends(auth.get_current_user)):
    detections = db.query(models.Detection).all()
    return schemas.StatsOut(
        total_requests=db.query(models.RequestLog).count(),
        total_detections=len(detections),
        by_decision=dict(Counter(d.decision for d in detections)),
        by_attack_type=dict(Counter(d.attack_type for d in detections if d.attack_type)),
    )
