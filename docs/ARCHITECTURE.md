# ShieldNet Architecture

## Request flow

1. A request hits the **ModSecurity WAF** (reverse proxy, OWASP CRS).
2. ModSecurity scores the request against CRS rules (SQLi, XSS, LFI/RFI,
   protocol anomalies) and writes an audit log entry.
3. Request metadata (method, URI, headers, body sample, ModSecurity rule hits,
   client IP, timestamp) is sent to the **FastAPI backend** and stored in
   **PostgreSQL** (`request_logs`).
4. The **hybrid scoring engine** combines three signals:
   - `rule_score` — normalised ModSecurity CRS anomaly score
   - `ml_score` — malicious-probability from the trained classifier
     (XGBoost / Random Forest) over extracted request features
   - `anomaly_score` — Isolation Forest outlier score vs. normal traffic
5. Combined risk score → decision:
   - `< RISK_MONITOR_THRESHOLD` → allow
   - `< RISK_BLOCK_THRESHOLD` → allow + flag (monitor)
   - `>= RISK_BLOCK_THRESHOLD` → block
6. Decisions are stored (`detections`) and surfaced in the **React dashboard**.

## Data model (sketch, finalised in Phase 1/3)

- `request_logs` — id, timestamp, ip, method, uri, headers (jsonb), body_sample,
  user_agent, modsec_rule_ids, modsec_score
- `detections` — request_id (FK), rule_score, ml_score, anomaly_score,
  risk_score, decision, attack_type, model_version
- `training_labels` — request_id (FK), label (benign / sqli / xss / traversal /
  other), source (dataset / manual / rule-derived)

## ML features (Phase 3)

Per request: URI length, arg count, arg length stats, special-character ratios,
entropy of payload, keyword hits (union/select/script/etc.), header anomalies,
method/encoding flags. Training starts from the CSIC-2010 HTTP dataset plus
ShieldNet's own logged traffic.

## Deployment

- Docker Compose: `db`, `waf`, `target-app` (Phase 0), `backend` (Phase 1).
- Frontend: Vercel, configured with the backend API URL as an env var.
- ModSecurity cannot run on Vercel's serverless platform, so the WAF/backend
  run on a Docker host (local machine for development and demo).
