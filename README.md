# ShieldNet — AI-Powered Intelligent Web Security Platform

ShieldNet is a Web Application Firewall (WAF) that combines three detection layers
into a single risk decision for every HTTP request:

1. **Rule-based detection** — ModSecurity with the OWASP Core Rule Set (CRS)
2. **Machine-learning detection** — XGBoost / Random Forest classifiers trained on
   logged request data
3. **Anomaly detection** — statistical / isolation-forest scoring of how unusual a
   request is compared to normal traffic

Each layer produces a score. A hybrid scoring engine combines them into one risk
score and decides: **allow**, **monitor**, or **block**.

## Architecture

```
Client ──► ModSecurity WAF (OWASP CRS, reverse proxy) ──► Target web app
                  │
                  │ audit log / request metadata
                  ▼
           FastAPI backend ──► PostgreSQL (request logs + training data)
                  │
                  ├── ML service (XGBoost / Random Forest)
                  ├── Anomaly detection
                  └── Hybrid scoring engine ──► allow / monitor / block
                  │
                  ▼
           React dashboard (deployed on Vercel)
           live alerts · blocked requests · traffic · model stats
```

> Deployment note: ModSecurity needs a persistent process, so the WAF, backend
> and database run in Docker. Only the React dashboard is deployed on Vercel;
> it talks to the backend over its API URL.

## Tech stack

| Layer | Technology |
|---|---|
| WAF | ModSecurity + OWASP CRS (nginx) |
| Backend API | Python, FastAPI |
| Database | PostgreSQL |
| ML | XGBoost, Random Forest, scikit-learn (Isolation Forest) |
| Frontend | React (Vite) |
| Infra | Docker Compose · Vercel (frontend only) |

## Repository structure

```
shieldnet/
├── frontend/     React dashboard (Vercel)
├── backend/      FastAPI service — logging, /analyze, dashboard APIs
├── ml/           Feature extraction, training, model artefacts
├── waf/          ModSecurity / CRS configuration and notes
├── target-app/   Demo web app that ShieldNet protects
├── docs/         Architecture and roadmap
└── docker-compose.yml
```

## Quick start (development)

```bash
cp .env.example .env
docker compose up -d --build
# WAF on http://localhost:8080 (proxies to the target app)
# Backend API on http://localhost:8000 — try GET /health, POST /analyze
```

The dashboard is added in Phase 5 — see
[docs/ROADMAP.md](docs/ROADMAP.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Roadmap

- **Phase 0** — Repo scaffold, Docker Compose (PostgreSQL + ModSecurity) ✅
- **Phase 1** — FastAPI backend: request logging to PostgreSQL, `/analyze` endpoint ✅
- **Phase 2** — ModSecurity + OWASP CRS live in front of the demo target app ✅
- **Phase 3** — ML detection: feature extraction + XGBoost / Random Forest training ✅
- **Phase 4** — Anomaly detection + hybrid scoring engine
- **Phase 5** — React dashboard on Vercel
- **Phase 6** — End-to-end attack tests (SQLi, XSS, path traversal), demo + docs

## Status

Academic / portfolio project under active development. The ML "block" decisions
are a demonstration of hybrid detection design — not a production security product.

## License

Apache-2.0 — see [LICENSE](LICENSE).
