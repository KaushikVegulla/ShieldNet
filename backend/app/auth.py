"""Authentication for the ShieldNet console.

Design (see docs/DEMO.md):
- Passwords are hashed with Argon2id (argon2-cffi PasswordHasher) and only
  the hash is stored.
- Login returns a short-lived JWT access token (HS256, JWT_SECRET) that the
  dashboard sends as `Authorization: Bearer ...` on every API call.
- A long-lived refresh token is set as an httpOnly cookie; only its SHA-256
  hash is stored, so refresh sessions can be rotated and revoked (logout).
- /ingest and /analyze are machine endpoints: they accept either a user JWT
  or the shared X-API-Key (INGEST_API_KEY). When no API key is configured
  (local development), they are open.
- Login attempts are rate-limited in memory (per email+IP). Single-instance
  scope is fine for this deployment; a multi-instance setup would move the
  counters to Redis.
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import get_db

ALGORITHM = "HS256"
REFRESH_COOKIE = "shieldnet_refresh"
REFRESH_COOKIE_PATH = "/auth"

_ph = PasswordHasher()

# --- login rate limiting (in-memory): max failures per window per email+IP ---
_MAX_FAILURES = 5
_WINDOW_SECONDS = 300
_failures: dict[str, list[float]] = {}


def _rate_key(email: str, ip: str) -> str:
    return f"{email.lower()}|{ip}"


def check_login_rate_limit(email: str, ip: str) -> None:
    now = time.time()
    key = _rate_key(email, ip)
    recent = [t for t in _failures.get(key, []) if now - t < _WINDOW_SECONDS]
    _failures[key] = recent
    if len(recent) >= _MAX_FAILURES:
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again in a few minutes.")


def record_login_failure(email: str, ip: str) -> None:
    _failures.setdefault(_rate_key(email, ip), []).append(time.time())


def clear_login_failures(email: str, ip: str) -> None:
    _failures.pop(_rate_key(email, ip), None)


# --- passwords ---

def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# --- access tokens (JWT) ---

def create_access_token(email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def _decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if payload.get("type") != "access" or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload["sub"]


def get_current_user(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> models.User:
    """FastAPI dependency: require a valid Bearer access token."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    email = _decode_access_token(authorization[len("Bearer "):])
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _valid_bearer(authorization: str, db: Session) -> bool:
    if not authorization.startswith("Bearer "):
        return False
    try:
        email = _decode_access_token(authorization[len("Bearer "):])
    except HTTPException:
        return False
    return db.query(models.User).filter(models.User.email == email).first() is not None


def require_write_access(
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
) -> None:
    """Dependency for /ingest and /analyze: a valid user JWT or the shared
    X-API-Key passes. When INGEST_API_KEY is not configured (local dev),
    the endpoints are open."""
    if _valid_bearer(authorization, db):
        return
    if settings.ingest_api_key and secrets.compare_digest(x_api_key, settings.ingest_api_key):
        return
    if not settings.ingest_api_key:
        return
    raise HTTPException(status_code=401, detail="Valid token or API key required")


# --- refresh tokens (hashed, rotating, revocable) ---

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_refresh_token(db: Session, user: models.User) -> str:
    raw = secrets.token_urlsafe(48)
    db.add(models.RefreshToken(
        user_id=user.id,
        token_hash=_hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
    ))
    db.commit()
    return raw


def verify_refresh_token(db: Session, raw: str) -> models.RefreshToken | None:
    if not raw:
        return None
    record = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == _hash_token(raw))
        .first()
    )
    if record is None or record.revoked:
        return None
    expires = record.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        return None
    return record


def rotate_refresh_token(db: Session, record: models.RefreshToken) -> str:
    """Revoke the presented token and issue a fresh one for the same user."""
    record.revoked = True
    db.commit()
    return create_refresh_token(db, record.user)


def revoke_refresh_token(db: Session, raw: str) -> None:
    record = verify_refresh_token(db, raw)
    if record is not None:
        record.revoked = True
        db.commit()


# --- seed user ---

def ensure_seed_user(db: Session) -> None:
    """Create the configured admin user on first run (demo account by
    default; override ADMIN_EMAIL / ADMIN_PASSWORD via env)."""
    existing = db.query(models.User).filter(models.User.email == settings.admin_email).first()
    if existing is None:
        db.add(models.User(
            email=settings.admin_email,
            password_hash=hash_password(settings.admin_password),
        ))
        db.commit()
