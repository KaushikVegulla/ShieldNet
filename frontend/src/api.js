// ShieldNet backend API client.
// If the backend is unreachable (e.g. the dashboard is on Vercel but the
// backend runs on your laptop), the UI falls back to clearly-labelled
// demo data instead of showing a dead page.

export const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

/* --- Auth session -------------------------------------------------------
   The access token lives only in this module variable (never localStorage).
   The refresh token is an httpOnly cookie set by the backend; the browser
   sends it automatically on credentialed /auth calls. On a 401 we try one
   silent refresh, then retry the original request. */

let accessToken = null;
let sessionUser = null; // { email, name } of the signed-in user

export function hasAccessToken() {
  return Boolean(accessToken);
}

export function getSessionUser() {
  return sessionUser;
}

function acceptToken(body) {
  accessToken = body.access_token;
  sessionUser = { email: body.email, name: body.name || null };
}

function authHeaders() {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
}

async function postAuth(path, body) {
  const resp = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return resp;
}

// Returns true when a session was restored/renewed.
export async function refreshSession() {
  try {
    const resp = await postAuth("/auth/refresh");
    if (!resp.ok) { accessToken = null; sessionUser = null; return false; }
    acceptToken(await resp.json());
    return true;
  } catch {
    accessToken = null;
    sessionUser = null;
    return false;
  }
}

// Throws an Error with .status and .detail for HTTP failures; network
// failures have no .status.
async function authCall(path, payload) {
  const resp = await postAuth(path, payload);
  if (!resp.ok) {
    const err = new Error(`${path} -> ${resp.status}`);
    err.status = resp.status;
    try { err.detail = (await resp.json()).detail; } catch { /* keep status only */ }
    throw err;
  }
  const body = await resp.json();
  acceptToken(body);
  return body;
}

export async function apiLogin(email, password) {
  return authCall("/auth/login", { email, password });
}

export async function apiRegister(name, email, password) {
  return authCall("/auth/register", { name, email, password });
}

export async function apiLogout() {
  try { await postAuth("/auth/logout"); } catch { /* session is dropped locally either way */ }
  accessToken = null;
  sessionUser = null;
}

async function get(path, retried = false) {
  const resp = await fetch(`${API_BASE}${path}`, { headers: authHeaders(), credentials: "include" });
  if (resp.status === 401 && !retried && (await refreshSession())) {
    return get(path, true);
  }
  if (!resp.ok) throw new Error(`${path} -> ${resp.status}`);
  return resp.json();
}

export async function fetchDashboard() {
  const [stats, detections, logs, metrics] = await Promise.all([
    get("/stats"),
    get("/detections?limit=25"),
    get("/logs?limit=25"),
    get("/model-metrics").catch(() => ({ classifier: null, anomaly: null })),
  ]);
  return { stats, detections, logs, metrics, demo: false };
}

const now = new Date();
const minsAgo = (m) => new Date(now - m * 60000).toISOString();

export const DEMO_DATA = {
  demo: true,
  stats: {
    total_requests: 1284,
    total_detections: 342,
    by_decision: { allow: 1093, monitor: 118, block: 73 },
    by_attack_type: { sqli: 41, xss: 27, traversal: 12, rce: 5, anomaly: 9 },
  },
  detections: [
    { id: 5, request_id: 105, created_at: minsAgo(2), rule_score: 75, ml_score: 100, anomaly_score: 51.5, risk_score: 80.2, decision: "block", attack_type: "sqli", model_version: "ml-v1" },
    { id: 4, request_id: 104, created_at: minsAgo(6), rule_score: 40, ml_score: 70, anomaly_score: 81.3, risk_score: 56.7, decision: "monitor", attack_type: "traversal", model_version: "ml-v1" },
    { id: 3, request_id: 103, created_at: minsAgo(11), rule_score: 75, ml_score: 98, anomaly_score: 44.1, risk_score: 76.9, decision: "block", attack_type: "xss", model_version: "ml-v1" },
    { id: 2, request_id: 102, created_at: minsAgo(18), rule_score: 0, ml_score: 32, anomaly_score: 0, risk_score: 11.2, decision: "allow", attack_type: null, model_version: "ml-v1" },
    { id: 1, request_id: 101, created_at: minsAgo(26), rule_score: 15, ml_score: 22, anomaly_score: 30.4, risk_score: 16.6, decision: "allow", attack_type: "probing", model_version: "ml-v1" },
  ],
  logs: [
    { id: 105, created_at: minsAgo(2), ip: "203.0.113.7", method: "GET", uri: "/search?q=' UNION SELECT username, password FROM users --", user_agent: "sqlmap/1.7", modsec_rule_ids: ["942100"], modsec_score: 5 },
    { id: 104, created_at: minsAgo(6), ip: "198.51.100.23", method: "GET", uri: "/static/%2e%2e%2f%2e%2e%2f.env", user_agent: "curl/8.0", modsec_rule_ids: ["930120"], modsec_score: 5 },
    { id: 103, created_at: minsAgo(11), ip: "203.0.113.99", method: "POST", uri: "/comment", user_agent: "Mozilla/5.0", modsec_rule_ids: ["941110"], modsec_score: 5 },
    { id: 102, created_at: minsAgo(18), ip: "192.0.2.14", method: "GET", uri: "/product?id=2", user_agent: "Mozilla/5.0", modsec_rule_ids: [], modsec_score: null },
    { id: 101, created_at: minsAgo(26), ip: "198.51.100.8", method: "GET", uri: "/.env", user_agent: "python-requests/2.32", modsec_rule_ids: [], modsec_score: null },
  ],
  metrics: {
    classifier: { best_model: "random_forest", version: "ml-v1", dataset_rows: 2400,
      results: { random_forest: { accuracy: 1.0, precision: 1.0, recall: 1.0, f1: 1.0 },
                 xgboost: { accuracy: 1.0, precision: 1.0, recall: 1.0, f1: 1.0 } } },
    anomaly: { version: "anomaly-v1", benign_score_mean: 25.65, attack_score_mean: 60.38,
      attacks_scoring_over_40: 0.79, benign_scoring_over_40: 0.3208 },
  },
};

// Score one request against the live detection engine (POST /analyze).
// Used by the Website Scanner view; throws when the backend is unreachable.
export async function analyzeRequest(uri, retried = false) {
  const resp = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    credentials: "include",
    body: JSON.stringify({ method: "GET", uri }),
  });
  if (resp.status === 401 && !retried && (await refreshSession())) {
    return analyzeRequest(uri, true);
  }
  if (!resp.ok) throw new Error(`/analyze -> ${resp.status}`);
  return resp.json();
}

export async function fetchDashboardOrDemo() {
  try {
    return await fetchDashboard();
  } catch {
    return DEMO_DATA;
  }
}
