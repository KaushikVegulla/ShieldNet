# ShieldNet Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo scaffold: README, .gitignore, folder structure, docker-compose (PostgreSQL + ModSecurity) | ✅ Done |
| 1 | Backend API (FastAPI): request logging to PostgreSQL, `/analyze` endpoint | ✅ Done (baseline pattern scorer; ML/anomaly scores land in Phase 3–4) |
| 2 | ModSecurity WAF with OWASP CRS in front of a demo target app | ✅ Done (custom rules + JSON audit log + backend log shipper; runtime check happens on first `docker compose up`) |
| 3 | ML detection: feature extraction + XGBoost / Random Forest training on logged data | Planned |
| 4 | Anomaly detection layer + hybrid scoring engine | Planned |
| 5 | React dashboard (alerts, traffic, model stats) deployed on Vercel | Planned |
| 6 | End-to-end tests with attack payloads (SQLi / XSS), demo + docs | Planned |
