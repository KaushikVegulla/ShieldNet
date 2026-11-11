# Frontend — ShieldNet dashboard (React + Vite)

Live view of the hybrid detection engine:

- Stat cards: total requests, analyzed, blocked / monitored / allowed
- Decision and attack-type breakdowns
- Model stats (classifier + anomaly metrics from the backend `/model-metrics`)
- Recent detections table with rule / ML / anomaly / risk scores
- Recent request log with ModSecurity CRS rule IDs
- Auto-refreshes every 10 seconds

## Data source

Reads `VITE_API_BASE_URL` (default `http://localhost:8000`). If the backend
is unreachable — e.g. you're viewing the Vercel deployment while the backend
runs on your laptop — the dashboard falls back to **clearly labelled demo
data** (amber "DEMO DATA" pill) instead of a dead page. Green "LIVE" pill =
real backend data.

## Run / build

```bash
npm install
npm run dev     # http://localhost:5173
npm run build   # -> dist/
```

## Deploy on Vercel

Import the GitHub repo, set **Root Directory = `frontend`**, and set the
`VITE_API_BASE_URL` environment variable to wherever the backend is
reachable from the viewer's browser (for a local-only backend, the Vercel
deployment will show demo data — that's expected).
