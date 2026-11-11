# ShieldNet Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo scaffold: README, .gitignore, folder structure, docker-compose (PostgreSQL + ModSecurity) | ✅ Done |
| 1 | Backend API (FastAPI): request logging to PostgreSQL, `/analyze` endpoint | ✅ Done (baseline pattern scorer; ML/anomaly scores land in Phase 3–4) |
| 2 | ModSecurity WAF with OWASP CRS in front of a demo target app | ✅ Done (custom rules + JSON audit log + backend log shipper; runtime check happens on first `docker compose up`) |
| 3 | ML detection: feature extraction + XGBoost / Random Forest training on logged data | ✅ Done (synthetic starter dataset; CSIC-2010 + own logged traffic is the next data iteration) |
| 4 | Anomaly detection layer + hybrid scoring engine | ✅ Done (Isolation Forest, weights rule .50 / ML .35 / anomaly .15, strong-rule floor) |
| 5 | React dashboard (alerts, traffic, model stats) deployed on Vercel | ✅ Built and production-build verified; Vercel project link pending team access |
| 6 | End-to-end tests with attack payloads (SQLi / XSS), demo + docs | ✅ Done (12-case battery passing; WAF-level script needs the Docker stack) |
