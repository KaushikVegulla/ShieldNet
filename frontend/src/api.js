// ShieldNet backend API client.
// If the backend is unreachable (e.g. the dashboard is on Vercel but the
// backend runs on your laptop), the UI falls back to clearly-labelled
// demo data instead of showing a dead page.

export const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function get(path) {
  const resp = await fetch(`${API_BASE}${path}`);
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

export async function fetchDashboardOrDemo() {
  try {
    return await fetchDashboard();
  } catch {
    return DEMO_DATA;
  }
}
