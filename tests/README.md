# ShieldNet tests

| Suite | What it covers | Run |
|---|---|---|
| `backend/tests/` | Backend API, baseline scorer, hybrid engine, audit-log parser (14 tests) | `cd backend && pytest` |
| `target-app/tests/` | Demo app routes incl. simulated SQLi login (5 tests) | `cd target-app && pytest` |
| `ml/tests/` | Feature extraction (3 tests) | `cd ml && pytest` |
| `tests/test_attack_battery.py` | End-to-end attack battery through `/analyze` with all models loaded (12 cases) | `pytest tests/` from repo root |
| `tests/run_e2e.sh` | WAF-level checks through ModSecurity on :8080 (needs Docker stack) | `bash tests/run_e2e.sh` |

The attack battery needs the trained artefacts first:

```bash
python ml/generate_dataset.py && python ml/train.py && python ml/train_anomaly.py
```

Without them it skips (the unit suites still cover rules-only behaviour).
Measured battery results and the demo script live in `docs/DEMO.md`.
