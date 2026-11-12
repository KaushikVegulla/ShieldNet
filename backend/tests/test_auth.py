"""Auth tests: JWT login, protected endpoints, refresh rotation, logout,
login rate limiting. Shares the app/DB with test_api.py (same import
pattern); each test builds its own TestClient so headers/cookies are
isolated."""

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./shieldnet_test.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN = {"email": "admin@shieldnet.io", "password": "shieldnet"}


def _login(client: TestClient):
    r = client.post("/auth/login", json=ADMIN)
    assert r.status_code == 200, r.text
    return r


def test_login_success_returns_token_and_refresh_cookie():
    client = TestClient(app)
    r = _login(client)
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["email"] == ADMIN["email"]
    assert body["access_token"]
    assert client.cookies.get("shieldnet_refresh")


def test_login_wrong_password_is_generic_401():
    client = TestClient(app)
    r = client.post("/auth/login", json={"email": ADMIN["email"], "password": "wrong-password"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_read_endpoints_require_auth():
    client = TestClient(app)
    for path in ("/stats", "/logs", "/detections", "/model-metrics", "/auth/me"):
        assert client.get(path).status_code == 401, path


def test_read_endpoints_accept_access_token():
    client = TestClient(app)
    token = _login(client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    for path in ("/stats", "/logs", "/detections", "/model-metrics", "/auth/me"):
        assert client.get(path, headers=headers).status_code == 200, path
    assert client.get("/auth/me", headers=headers).json()["email"] == ADMIN["email"]


def test_garbage_token_is_rejected():
    client = TestClient(app)
    r = client.get("/stats", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_refresh_rotates_and_rejects_the_old_token():
    client = TestClient(app)
    _login(client)
    old_raw = client.cookies.get("shieldnet_refresh")
    r = client.post("/auth/refresh")
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]
    new_raw = client.cookies.get("shieldnet_refresh")
    assert new_raw and new_raw != old_raw
    # Replaying the rotated-out token must fail.
    replay = TestClient(app)
    replay.cookies.set("shieldnet_refresh", old_raw)
    assert replay.post("/auth/refresh").status_code == 401


def test_logout_revokes_the_refresh_session():
    client = TestClient(app)
    _login(client)
    assert client.post("/auth/logout").status_code == 200
    assert client.post("/auth/refresh").status_code == 401


def test_login_rate_limit_kicks_in_after_repeated_failures():
    client = TestClient(app)
    victim = {"email": "victim@example.com", "password": "nope"}
    for _ in range(5):
        assert client.post("/auth/login", json=victim).status_code == 401
    assert client.post("/auth/login", json=victim).status_code == 429


def test_analyze_and_ingest_open_when_no_api_key_configured():
    # Local-dev default (INGEST_API_KEY unset): machine endpoints accept
    # unauthenticated calls; production sets the key (see docs/HOSTING.md).
    client = TestClient(app)
    assert client.post("/analyze", json={"method": "GET", "uri": "/products?id=1"}).status_code == 200
    assert client.post("/ingest", json={"method": "GET", "uri": "/about"}).status_code == 201
