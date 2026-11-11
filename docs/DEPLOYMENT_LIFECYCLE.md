# ShieldNet — WAF Deployment Checklist & Lifecycle

How ShieldNet is rolled out, following the standard WAF lifecycle:
plan → deploy in learning mode → tune → enforce → operate. Each stage
names the ShieldNet setting or tool that implements it.

## 1. Preparation & planning

- Identify the assets being protected (the demo target app on port 5000;
  in a real deployment: domains, ports 80/443, key endpoints like `/login`).
- Security policy baseline: OWASP Top 10 coverage via the CRS, ShieldNet
  hybrid thresholds (monitor ≥ 40, block ≥ 75), rate limiting out of scope
  for the demo.
- Deployment mode: **reverse proxy** — ModSecurity sits in front of the app
  in `docker-compose.yml`.
- Output: this document + `docs/ARCHITECTURE.md` (network/data-flow diagram).

## 2. Initial deployment — learning / passive mode

Goal: baseline traffic patterns, collect comprehensive logs, **no blocking**.

```bash
# .env
WAF_RULE_ENGINE=DetectionOnly
docker compose up -d
```

- ModSecurity inspects and logs but never blocks (`SecRuleEngine DetectionOnly`).
- Ship the audit log to PostgreSQL: `backend/scripts/parse_audit_log.py`.
- Let this run until the log has representative normal traffic — it is
  also the raw material for ML training data.

## 3. Policy tuning & validation

Goal: minimise false positives before enforcement. Iterative loop:

1. Review WAF logs + the dashboard's request feed; list false positives
   and unexpected anomalies.
2. Refine: add CRS exclusions in `waf/rules/REQUEST-900-SHIELDNET-BEFORE-CRS.conf`
   (the `ctl:auditEngine=Off` health-check rule is the pattern to copy),
   adjust hybrid thresholds via `RISK_MONITOR_THRESHOLD` /
   `RISK_BLOCK_THRESHOLD`, retrain models on the enlarged log.
3. Test with staging traffic: run the attack battery
   (`pytest tests/`, `bash tests/run_e2e.sh`) plus normal-use scripts and
   confirm attacks score high while normal use stays *allow*.

## 4. Enforcement & production cutover — active blocking

Goal: protect production traffic with validated rules.

```bash
# .env
WAF_RULE_ENGINE=On
docker compose up -d
```

- ModSecurity CRS blocks at the edge (403); the hybrid engine blocks /
  monitors at the analyzer.
- Monitor the dashboard closely post-cutover: blocked count, monitored
  queue, and any legitimate-traffic complaints.

## 5. Ongoing operations & optimization

- **Continuous monitoring** — dashboard (live feed, decision/attack
  breakdowns); review alerts daily during the first weeks.
- **Threat-intel updates** — update the CRS image regularly
  (`docker compose pull waf`), review new CRS releases.
- **Regular audits & testing** — re-run the attack battery after every
  rule/model change; add new payloads as they're discovered.
- **Model refresh** — periodically retrain on newly logged traffic
  (`ml/train.py`, `ml/train_anomaly.py`) and compare metrics before
  promoting a new model.
- **Incident response** — for a suspected breach: preserve PostgreSQL
  `request_logs` + ModSecurity audit logs first, then tune rules.

*Security is sustained by this loop, not by the initial deployment.*
