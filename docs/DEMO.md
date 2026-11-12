# ShieldNet Demo Guide

## 1. Start the stack

```bash
cp .env.example .env
pip install -r ml/requirements.txt
python ml/generate_dataset.py && python ml/train.py && python ml/train_anomaly.py
docker compose up -d --build
```

- Target app via WAF: http://localhost:8080
- Backend API: http://localhost:8000 (`/docs` for Swagger)
- Dashboard: `cd frontend && npm run dev` → http://localhost:5173
  (or the Vercel deployment). The console opens on an **auth page** with
  Sign in / Create account — evaluators can register their own account
  (real backend auth: Argon2id password hash + JWT access token +
  rotating httpOnly refresh cookie). The owner's seeded account is
  `admin@shieldnet.io` / `shieldnet` (configurable via ADMIN_EMAIL /
  ADMIN_PASSWORD). Logout is in the user menu (top right).

## 2. Demo script (5 minutes)

1. **Normal traffic** — open the shop through the WAF, search "coffee mug",
   log in as demo/demo. Dashboard shows the requests as *allow*, risk ≈ 0.
2. **SQL injection** — search for `' UNION SELECT username, password FROM users --`.
   Through the WAF, ModSecurity CRS returns **403**. Sent to `/analyze`
   directly, the hybrid engine blocks it too (see results below).
3. **XSS** — post `<script>alert(document.cookie)</script>` as a comment:
   blocked by CRS at the WAF and by the hybrid engine at the analyzer.
4. **The interesting case** — `GET /product?id=1 AND SLEEP(5)`: no classic
   rule pattern fires hard, but the ML model scores it 93.5, so the hybrid
   engine's ML floor raises it to *monitor*. This is the "AI layer catches
   what rules miss" moment.
5. **Dashboard** — show the detections table: every request carries its rule,
   ML and anomaly scores side by side, plus the CRS rule IDs in the log feed.

## 3. Measured results — attack battery (all models loaded)

From `tests/test_attack_battery.py` — 12/12 passing:

| Case | Rule | ML | Anomaly | Risk | Decision |
|---|---|---|---|---|---|
| Benign product page | 0 | 0 | 0 | 0 | **allow** |
| Benign search | 0 | 0 | 0 | 0 | **allow** |
| Benign login | 0 | 0 | 81.1 | 12.2 | **allow** |
| SQLi UNION SELECT | 75 | 100 | 51.5 | 80.2 | **block** |
| SQLi login bypass | 60 | 100 | 78.2 | 76.7 | **block** |
| SQLi SLEEP probe | 30 | 93.5 | 16.3 | 55.0 | **monitor** |
| XSS script tag | 75 | 86.5 | 48.4 | 75.0 | **block** |
| XSS img onerror | 75 | 100 | 72.4 | 83.4 | **block** |
| Traversal ../../etc/passwd | 55 | 38.5 | 26.6 | 45.0 | **monitor** |
| Traversal encoded .env | 40 | 62 | 68.5 | 52.0 | **monitor** |
| RCE `; cat /etc/passwd` | 85 | 92 | 15.8 | 77.1 | **block** |
| RCE curl subshell | 55 | 96.5 | 59.0 | 70.1 | **monitor** |

The battery earned its keep: its first run exposed three real weaknesses —
a SLEEP() probe being allowed, `../../etc/passwd` slipping under the monitor
threshold, and a broken probing regex — all fixed in the rule scorer / hybrid
engine and re-verified.

## 4. Known limitations (say these before your examiner does)

- **Training data is synthetic.** Perfect classifier scores (F1 1.0) are a
  pipeline check, not real-world accuracy. Next iteration: CSIC-2010 +
  ShieldNet's own logged traffic.
- **The anomaly model over-flags** (32% of benign synthetic traffic scores
  > 40; a benign login scored 81). That's why its hybrid weight is only
  0.15 and why it can't block on its own.
- **Registration is open** — anyone who can reach the hosted backend can
  create a console account (that's deliberate for evaluation; a real
  deployment would close sign-ups or gate them behind invites, change
  `ADMIN_PASSWORD`, and add 2FA). The auth mechanism itself is
  production-shaped: Argon2id hashing, JWT access tokens, rotating
  refresh tokens, login rate limiting. Self-service password reset is
  not implemented yet.
- **Machine endpoints in local dev**: with `INGEST_API_KEY` unset,
  `/ingest` and `/analyze` accept unauthenticated calls (the WAF pipeline
  and attack battery rely on this locally). Production sets the key, and
  those endpoints then require the `X-API-Key` header or a user JWT.
- **The WAF-level script** (`tests/run_e2e.sh`) needs the Docker stack and
  is verified manually, not in CI.
- This is an academic demonstration, not a production WAF.
