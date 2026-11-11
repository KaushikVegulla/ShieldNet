# Hosting ShieldNet live (Option B)

Goal: the Vercel dashboard shows **LIVE** data. That needs the backend +
PostgreSQL on a public HTTPS host — Vercel only hosts the frontend.

```
Browser -> Vercel (React dashboard) -> Render (FastAPI backend) -> Render PostgreSQL
Laptop   -> Docker (ModSecurity WAF + target app) --/analyze, /ingest--> Render backend (optional)
```

## 1. Deploy the backend on Render (free)

1. Create an account at [render.com](https://render.com) (sign in with GitHub).
2. **New → Blueprint** → connect `KaushikVegulla/ShieldNet` → **Apply**.
   The repo's `render.yaml` creates:
   - web service `shieldnet-backend` (Docker, from `backend/Dockerfile`,
     health check `/health`)
   - free PostgreSQL `shieldnet-db`, injected as `DATABASE_URL`
3. Wait for the first deploy to go green, then open
   `https://shieldnet-backend.onrender.com/health` → `{"status":"ok",...}`.
   (Your exact URL is on the service page — use it below.)

Free-tier notes: the web service sleeps after inactivity (first request
takes ~30–60s to wake) and the free database is time-limited — fine for a
demo, not for production.

## 2. Point the dashboard at it

1. Vercel → project `shieldnet` → **Settings → Environment Variables**:
   - `VITE_API_BASE_URL` = `https://shieldnet-backend.onrender.com`
     (no trailing slash)
2. While you're in Settings: **General → Root Directory = `frontend`**
   (if not already set).
3. **Deployments → ⋯ → Redeploy** (env vars apply only to new builds).

Open the site: the pill should now read **● LIVE**. The dashboard starts
empty — send it traffic:

```bash
curl -X POST https://shieldnet-backend.onrender.com/analyze \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","uri":"/search?q='\'' UNION SELECT username, password FROM users --"}'
```

## 3. What runs where (be able to explain this)

- The **hosted backend** serves rule-based scoring immediately.
  `ml_score` / `anomaly_score` return `null` there because the trained
  model files are git-ignored binaries and are not in the repo — the
  hybrid engine renormalises over the rule signal. To enable ML on the
  host, the models would need to be baked into the backend image or
  fetched from object storage at boot (future work).
- The **WAF (ModSecurity)** still runs in Docker on your machine — it
  cannot run on Render's free web service model used here or on Vercel.
  Your local stack can ship its logs to the hosted backend with
  `backend/scripts/parse_audit_log.py --backend https://shieldnet-backend.onrender.com`.

## Alternative: Railway

Railway works the same way: deploy from the repo with the backend
Dockerfile, add a PostgreSQL plugin, set `DATABASE_URL`, then use the
generated domain as `VITE_API_BASE_URL` in Vercel.
