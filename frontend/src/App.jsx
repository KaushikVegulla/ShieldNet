import { useCallback, useEffect, useMemo, useState } from "react";
import { API_BASE, fetchDashboardOrDemo } from "./api.js";

function Bars({ data, color }) {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (!entries.length) return <p className="muted">No data yet</p>;
  return (
    <div>
      {entries.map(([label, value]) => (
        <div className="bar-row" key={label}>
          <span className="bar-label">{label}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(value / max) * 100}%`, background: color(label) }} />
          </div>
          <span className="bar-value">{value}</span>
        </div>
      ))}
    </div>
  );
}

const decisionColor = (d) => ({ block: "#e5484d", monitor: "#f5a524", allow: "#30a46c" }[d] || "#8892a4");
const attackColor = () => "#6e7fe0";

export default function App() {
  const [data, setData] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);

  const load = useCallback(async () => {
    setData(await fetchDashboardOrDemo());
    setUpdatedAt(new Date());
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  const logsById = useMemo(() => {
    const map = {};
    (data?.logs || []).forEach((l) => { map[l.id] = l; });
    return map;
  }, [data]);

  if (!data) return <div className="page"><p className="muted">Loading ShieldNet dashboard…</p></div>;

  const { stats, detections, logs, metrics } = data;
  const clf = metrics?.classifier;
  const clfBest = clf?.results?.[clf?.best_model];
  const anom = metrics?.anomaly;

  return (
    <div className="page">
      <header>
        <div>
          <h1>🛡️ ShieldNet</h1>
          <p className="muted">AI-powered web application firewall — hybrid detection dashboard</p>
        </div>
        <div className="header-right">
          <span className={`pill ${data.demo ? "pill-demo" : "pill-live"}`}>
            {data.demo ? "DEMO DATA — backend not reachable" : "● LIVE"}
          </span>
          <button onClick={load}>Refresh</button>
          <span className="muted small">
            API: {API_BASE}{updatedAt ? ` · updated ${updatedAt.toLocaleTimeString()}` : ""}
          </span>
        </div>
      </header>

      <section className="cards">
        <div className="card"><span className="card-num">{stats.total_requests}</span><span className="card-label">Total requests</span></div>
        <div className="card"><span className="card-num">{stats.total_detections}</span><span className="card-label">Analyzed</span></div>
        <div className="card danger"><span className="card-num">{stats.by_decision.block || 0}</span><span className="card-label">Blocked</span></div>
        <div className="card warn"><span className="card-num">{stats.by_decision.monitor || 0}</span><span className="card-label">Monitored</span></div>
        <div className="card ok"><span className="card-num">{stats.by_decision.allow || 0}</span><span className="card-label">Allowed</span></div>
      </section>

      <section className="grid">
        <div className="panel">
          <h2>Decisions</h2>
          <Bars data={stats.by_decision} color={decisionColor} />
          <h2>Attack types</h2>
          <Bars data={stats.by_attack_type} color={attackColor} />
        </div>

        <div className="panel">
          <h2>Model stats</h2>
          {clf ? (
            <table className="kv">
              <tbody>
                <tr><td>Classifier</td><td>{clf.best_model} ({clf.version})</td></tr>
                <tr><td>Training rows</td><td>{clf.dataset_rows}</td></tr>
                {clfBest && <tr><td>F1 / accuracy (held-out)</td><td>{clfBest.f1} / {clfBest.accuracy}</td></tr>}
                {anom && <tr><td>Anomaly model</td><td>{anom.version} — benign mean {anom.benign_score_mean}, attack mean {anom.attack_score_mean}</td></tr>}
              </tbody>
            </table>
          ) : <p className="muted">No model metrics reported by the backend yet.</p>}
          <p className="muted small">Metrics are from the synthetic starter dataset — see ml/README.md in the repo for the honest caveats.</p>
        </div>
      </section>

      <section className="panel">
        <h2>Recent detections</h2>
        <table className="feed">
          <thead><tr><th>Time</th><th>Request</th><th>Rule</th><th>ML</th><th>Anomaly</th><th>Risk</th><th>Decision</th><th>Type</th></tr></thead>
          <tbody>
            {detections.map((d) => {
              const log = logsById[d.request_id];
              return (
                <tr key={d.id}>
                  <td>{new Date(d.created_at).toLocaleTimeString()}</td>
                  <td className="uri">{log ? `${log.method} ${log.uri}` : `#${d.request_id}`}</td>
                  <td>{d.rule_score}</td>
                  <td>{d.ml_score ?? "—"}</td>
                  <td>{d.anomaly_score ?? "—"}</td>
                  <td><strong>{d.risk_score}</strong></td>
                  <td><span className="tag" style={{ background: decisionColor(d.decision) }}>{d.decision}</span></td>
                  <td>{d.attack_type || "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Recent requests</h2>
        <table className="feed">
          <thead><tr><th>Time</th><th>IP</th><th>Request</th><th>CRS rules</th></tr></thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{new Date(l.created_at).toLocaleTimeString()}</td>
                <td>{l.ip || "—"}</td>
                <td className="uri">{l.method} {l.uri}</td>
                <td>{(l.modsec_rule_ids || []).join(", ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <footer className="muted small">
        ShieldNet — rules (ModSecurity CRS) + ML (XGBoost / Random Forest) + anomaly (Isolation Forest).
        Dashboard refreshes every 10s.
      </footer>
    </div>
  );
}
