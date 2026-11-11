# WAF — ModSecurity + OWASP CRS

The `waf` service in the root `docker-compose.yml` runs the official
`owasp/modsecurity-crs:nginx` image as a reverse proxy in front of
`target-app/` (port 5000). All traffic to http://localhost:8080 goes through
ModSecurity first.

## Configuration

Set via environment in `docker-compose.yml`:

- Paranoia level 1, blocking mode (inbound anomaly threshold 5, outbound 4)
- Audit log: JSON format at `/var/log/modsec_audit.log` (named volume `modsec-logs`)

Custom ShieldNet rules live in `rules/` and are mounted into the container:

- `REQUEST-900-SHIELDNET-BEFORE-CRS.conf` — health-check bypass, request tagging
- `REQUEST-949-SHIELDNET-AFTER-CRS.conf` — simulation-header block (used by the
  end-to-end tests), login-endpoint logging

> First-run check: after `docker compose up`, confirm nginx picked up the
> mounted rules with `docker compose logs waf` (a bad rule file fails startup).

## Feeding the backend

ModSecurity's JSON audit log is the training/logging data source:

```bash
python backend/scripts/parse_audit_log.py /path/to/modsec_audit.log \
    --backend http://localhost:8000
```

It extracts IP, method, URI, headers and the CRS rule IDs per transaction and
POSTs them to the backend `/ingest` endpoint (PostgreSQL `request_logs`).
