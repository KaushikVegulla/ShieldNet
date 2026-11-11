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

## Scoring

`/analyze` runs all three detection layers into the hybrid engine
(`app/hybrid.py`):

| Signal | Source | Weight |
|---|---|---|
| Rule score | `app/scoring.py` patterns + ModSecurity CRS score | 0.50 |
| ML score | `app/ml_scoring.py`, model from `MODEL_PATH` | 0.35 |
| Anomaly score | `app/anomaly_scoring.py`, model from `ANOMALY_MODEL_PATH` | 0.15 |

Weights renormalise over whichever signals are loaded — with no models
installed the backend still works on rules alone and returns `null` ML /
anomaly scores rather than invented numbers. A rule score ≥ 90 floors the
risk at 85 so known-bad patterns can't be diluted. Thresholds: `>= 40`
monitor, `>= 75` block (configurable via env).

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
