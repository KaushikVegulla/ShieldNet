# Backend (Phase 1)

FastAPI service. Responsibilities:

- Receive / ingest request metadata from the WAF audit pipeline
- Store request logs in PostgreSQL
- `POST /analyze` — score a request through the hybrid engine (Phase 4)
- Dashboard APIs for the React frontend (Phase 5)

Implementation starts in Phase 1.
