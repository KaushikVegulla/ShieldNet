# Backend — FastAPI service

Logs HTTP requests to PostgreSQL, scores them, and serves the dashboard APIs.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| GET | `/health` | Liveness check |
| POST | `/ingest` | Log a request only (e.g. from the ModSecurity audit pipeline) |
| POST | `/analyze` | Log + score a request, store a detection, return the decision |
| GET | `/logs` | Recent request logs |
| GET | `/detections` | Recent detections |
| GET | `/stats` | Totals by decision and attack type (dashboard) |

## Scoring (Phase 1)

`/analyze` currently uses a transparent baseline pattern scorer
(`app/scoring.py`): SQLi / XSS / traversal / RCE / probing patterns plus the
ModSecurity CRS score, combined into a 0–100 risk score.
Thresholds: `>= 40` monitor, `>= 75` block (configurable via env).

Phase 3 adds the ML score (XGBoost / Random Forest) and Phase 4 the anomaly
score + full hybrid combination. `ml_score` / `anomaly_score` are `null` until then.

## Run

```bash
# whole stack (from repo root)
docker compose up -d --build
curl http://localhost:8000/health

# or locally
pip install -r requirements-dev.txt
DATABASE_URL=sqlite:///./dev.db uvicorn app.main:app --reload
pytest            # 5 API tests, uses a local SQLite test DB
```
