# WAF (Phase 2)

ModSecurity + OWASP Core Rule Set, running as a reverse proxy in front of
`target-app/` (see the `waf` service in the root `docker-compose.yml`).

Phase 2 will add: CRS tuning, audit-log format for backend ingestion, and
custom ShieldNet rules. The audit log is the data source for PostgreSQL
request logging (Phase 1) and ML training data (Phase 3).
