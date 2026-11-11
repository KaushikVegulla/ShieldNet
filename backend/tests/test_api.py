import os

os.environ["DATABASE_URL"] = "sqlite:///./test_shieldnet.db"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_benign_request_is_allowed():
    r = client.post("/analyze", json={"method": "GET", "uri": "/products?id=42"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["risk_score"] < 40


def test_analyze_sqli_request_is_blocked():
    r = client.post(
        "/analyze",
        json={"method": "GET", "uri": "/search?q=' UNION SELECT username, password FROM users --"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["attack_type"] == "sqli"
    assert body["decision"] == "block"


def test_analyze_xss_request_scores_high():
    r = client.post(
        "/analyze",
        json={"method": "POST", "uri": "/comment", "body": "<script>alert(document.cookie)</script>"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["attack_type"] == "xss"
    assert body["decision"] in ("monitor", "block")


def test_model_metrics_shape():
    r = client.get("/model-metrics")
    assert r.status_code == 200
    body = r.json()
    assert "classifier" in body and "anomaly" in body


def test_ingest_and_stats():
    r = client.post("/ingest", json={"method": "GET", "uri": "/about"})
    assert r.status_code == 201
    stats = client.get("/stats").json()
    assert stats["total_requests"] >= 1
    assert stats["total_detections"] >= 1
