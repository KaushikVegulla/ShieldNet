import { useCallback, useEffect, useMemo, useState } from "react";
import { API_BASE, analyzeRequest, apiLogin, apiLogout, fetchDashboardOrDemo, refreshSession } from "./api.js";

/* ---------- small chart helpers (no chart library, pure SVG) ---------- */

function bucketize(items, minutes = 30, bucketMin = 5) {
  const n = Math.ceil(minutes / bucketMin);
  const buckets = new Array(n).fill(0);
  const now = Date.now();
  items.forEach((it) => {
    const t = new Date(it.created_at).getTime();
    const idx = Math.floor((t - (now - minutes * 60000)) / (bucketMin * 60000));
    if (idx >= 0 && idx < n) buckets[idx] += 1;
  });
  return buckets;
}

function Sparkline({ values, color }) {
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * 100},${26 - (v / max) * 22}`).join(" ");
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="spark">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" />
    </svg>
  );
}

function AreaChart({ seriesA, seriesB }) {
  const W = 560, H = 180, max = Math.max(2, ...seriesA, ...seriesB);
  const line = (s) => s.map((v, i) => `${(i / Math.max(1, s.length - 1)) * W},${H - 14 - (v / max) * (H - 30)}`).join(" ");
  const area = (s) => `0,${H} ${line(s)} ${W},${H}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="area-chart">
      <polygon points={area(seriesA)} fill="rgba(47,123,255,.22)" />
      <polyline points={line(seriesA)} fill="none" stroke="#2f7bff" strokeWidth="2" />
      <polyline points={line(seriesB)} fill="none" stroke="#e5484d" strokeWidth="2" />
    </svg>
  );
}

function Donut({ data }) {
  const colors = { sqli: "#e5484d", xss: "#f5a524", rce: "#2f7bff", traversal: "#8e4ec6", probing: "#30a46c", anomaly: "#12a594" };
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  const sum = entries.reduce((s, [, v]) => s + v, 0);
  const total = Math.max(1, sum); // divisor only — the centre label shows the real sum
  let acc = 0;
  const R = 52, C = 2 * Math.PI * R;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 140 140" className="donut">
        {entries.map(([label, v]) => {
          const frac = v / total, start = acc; acc += frac;
          return (
            <circle key={label} cx="70" cy="70" r={R} fill="none" stroke={colors[label] || "#8892a4"}
              strokeWidth="17" strokeDasharray={`${frac * C} ${C}`}
              strokeDashoffset={-start * C} transform="rotate(-90 70 70)" />
          );
        })}
        <text x="70" y="66" textAnchor="middle" className="donut-num">{sum}</text>
        <text x="70" y="84" textAnchor="middle" className="donut-sub">attacks</text>
      </svg>
      <div className="donut-legend">
        {entries.map(([label, v]) => (
          <div className="legend-row" key={label}>
            <span className="dot" style={{ background: colors[label] || "#8892a4" }} />
            <span className="legend-label">{label}</span>
            <span className="legend-val">{((v / total) * 100).toFixed(1)}%</span>
          </div>
        ))}
        {!entries.length && <p className="muted">No attacks recorded yet</p>}
      </div>
    </div>
  );
}

/* ---------- AI assistant (local, answers from live stats only) ---------- */

function assistantAnswer(q, ctx) {
  const s = q.toLowerCase();
  const { stats, lastEvent } = ctx;
  if (s.includes("block")) return `${stats.by_decision.block || 0} requests have been blocked so far, out of ${stats.total_requests} total requests analyzed.`;
  if (s.includes("monitor") || s.includes("suspicious")) return `${stats.by_decision.monitor || 0} requests are flagged for monitoring (risk 40–74).`;
  if (s.includes("attack type") || s.includes("most common") || s.includes("top attack")) {
    const top = Object.entries(stats.by_attack_type).sort((a, b) => b[1] - a[1])[0];
    return top ? `The most common attack type is ${top[0]} with ${top[1]} detections.` : "No attacks recorded yet.";
  }
  if (s.includes("accuracy") || s.includes("f1") || s.includes("model")) return ctx.modelLine;
  if (s.includes("latest") || s.includes("recent")) return lastEvent || "No security events yet.";
  if (s.includes("total") || s.includes("request")) return `${stats.total_requests} requests logged, ${stats.total_detections} analyzed by the hybrid engine.`;
  return "I can answer from live data: try 'how many blocked?', 'most common attack type?', 'model accuracy?' or 'latest event?'.";
}

/* ---------- main app ---------- */

const NAV = [
  ["overview", "🏠", "Overview"],
  ["live", "📊", "Live Monitoring"],
  ["threats", "🛡️", "Threat Detection"],
  ["intel", "🎯", "Attack Intelligence"],
  ["scanner", "🔍", "Website Scanner"],
  ["api", "🔌", "API Security"],
  ["db", "🗄️", "Database Guard"],
  ["assistant", "🤖", "AI Assistant"],
  ["incidents", "🚨", "Incident Response"],
  ["reports", "📄", "Reports"],
  ["settings", "⚙️", "Settings"],
];

const TYPE_LABELS = { sqli: "SQL Injection", xss: "XSS", rce: "Command Injection", traversal: "Path Traversal", probing: "Probing", anomaly: "Anomaly" };

// Trend of the second half of a bucket series vs the first half (real data only).
function trendPct(buckets) {
  const mid = Math.floor(buckets.length / 2);
  const a = buckets.slice(0, mid).reduce((s, v) => s + v, 0);
  const b = buckets.slice(mid).reduce((s, v) => s + v, 0);
  if (!a && !b) return null;
  if (!a) return { pct: 100, up: true };
  const pct = Math.round(((b - a) / a) * 100);
  return { pct: Math.abs(pct), up: pct >= 0 };
}

// Overview donut in the reference design: friendly type names, top 4 + Others,
// centre shows the real threat share (detections ÷ requests).
function ThreatDonut({ byType, totalRequests, totalDetections }) {
  const colors = { "SQL Injection": "#e5484d", XSS: "#f5a524", "Command Injection": "#2f7bff", "Path Traversal": "#8e4ec6", Probing: "#30a46c", Anomaly: "#12a594", Others: "#5b6b8c" };
  const raw = Object.entries(byType || {}).map(([k, v]) => [TYPE_LABELS[k] || k, v]).sort((a, b) => b[1] - a[1]);
  const entries = raw.slice(0, 4);
  const rest = raw.slice(4).reduce((s, [, v]) => s + v, 0);
  if (rest) entries.push(["Others", rest]);
  const sum = Math.max(1, raw.reduce((s, [, v]) => s + v, 0));
  const share = totalRequests ? ((totalDetections / totalRequests) * 100).toFixed(1) : "0.0";
  let acc = 0;
  const R = 52, C = 2 * Math.PI * R;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 140 140" className="donut">
        {entries.map(([label, v]) => {
          const frac = v / sum, start = acc; acc += frac;
          return (
            <circle key={label} cx="70" cy="70" r={R} fill="none" stroke={colors[label] || "#8892a4"}
              strokeWidth="17" strokeDasharray={`${frac * C} ${C}`}
              strokeDashoffset={-start * C} transform="rotate(-90 70 70)" />
          );
        })}
        <text x="70" y="66" textAnchor="middle" className="donut-num">{share}%</text>
        <text x="70" y="84" textAnchor="middle" className="donut-sub">Threats</text>
      </svg>
      <div className="donut-legend">
        {entries.map(([label, v]) => (
          <div className="legend-row" key={label}>
            <span className="dot" style={{ background: colors[label] || "#8892a4" }} />
            <span className="legend-label wide-label">{label}</span>
            <span className="legend-val">{((v / sum) * 100).toFixed(1)}%</span>
          </div>
        ))}
        {!entries.length && <p className="muted">No attacks recorded yet</p>}
      </div>
    </div>
  );
}

const BATTERY = [
  ["SQLi UNION SELECT", "block"], ["SQLi login bypass", "block"], ["SQLi SLEEP probe", "monitor"],
  ["XSS script tag", "block"], ["XSS img onerror", "block"], ["Traversal ../../etc/passwd", "monitor"],
  ["Traversal encoded .env", "monitor"], ["RCE ; cat /etc/passwd", "block"], ["RCE curl subshell", "monitor"],
  ["Benign product page", "allow"], ["Benign search", "allow"], ["Benign login", "allow"],
];

function Dashboard({ onLogout }) {
  const [view, setView] = useState("overview");
  const [data, setData] = useState(null);
  const [query, setQuery] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);
  const [chat, setChat] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [range, setRange] = useState("1h");
  const [menuOpen, setMenuOpen] = useState(false);
  const [scanUri, setScanUri] = useState("");
  const [scan, setScan] = useState(null);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState("");
  const [acked, setAcked] = useState({});

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
    const m = {};
    (data?.logs || []).forEach((l) => { m[l.id] = l; });
    return m;
  }, [data]);

  const events = useMemo(() => {
    if (!data) return [];
    return data.detections.map((d) => {
      const log = logsById[d.request_id];
      return { ...d, ip: log?.ip || "—", uri: log ? `${log.method} ${log.uri}` : `#${d.request_id}` };
    }).filter((e) => !query || `${e.ip} ${e.uri} ${e.attack_type || ""}`.toLowerCase().includes(query.toLowerCase()));
  }, [data, logsById, query]);

  if (!data) return <div className="boot">Loading ShieldNet console…</div>;

  const { stats, detections, logs, metrics } = data;
  const clf = metrics?.classifier;
  const clfBest = clf?.results?.[clf?.best_model];
  const anom = metrics?.anomaly;
  const RANGES = { "1h": [60, 5], "24h": [1440, 120], "7d": [10080, 840], "30d": [43200, 3600] };
  const [rMin, rBucket] = RANGES[range];
  const reqBuckets = bucketize(logs, rMin, rBucket);
  const blockBuckets = bucketize(detections.filter((d) => d.decision === "block"), rMin, rBucket);
  const reqTrend = trendPct(reqBuckets);
  const blockTrend = trendPct(blockBuckets);
  const avgRisk = detections.length ? (detections.reduce((s, d) => s + d.risk_score, 0) / detections.length) : 0;
  const topIps = Object.entries(logs.reduce((acc, l) => { if (l.ip) acc[l.ip] = (acc[l.ip] || 0) + 1; return acc; }, {}))
    .sort((a, b) => b[1] - a[1]).slice(0, 5);
  const lastEvent = events[0] ? `Latest event: ${events[0].attack_type || "request"} from ${events[0].ip} at ${new Date(events[0].created_at).toLocaleTimeString()} — ${events[0].decision} (risk ${events[0].risk_score}).` : null;
  const modelLine = clfBest
    ? `Classifier ${clf.best_model} (${clf.version}): F1 ${clfBest.f1}, accuracy ${clfBest.accuracy} on the held-out synthetic split. Treat as a pipeline check, not real-world accuracy.`
    : "No classifier metrics are loaded on the backend yet.";

  const summary = [
    `${stats.total_requests} requests monitored`,
    `${stats.by_decision.block || 0} threats blocked`,
    `${stats.by_decision.monitor || 0} flagged for monitoring`,
    clfBest ? `Model F1: ${clfBest.f1} (synthetic held-out)` : "Models not loaded",
  ];

  const ask = () => {
    const q = chatInput.trim();
    if (!q) return;
    setChat((c) => [...c, { who: "you", text: q }, { who: "ai", text: assistantAnswer(q, { stats, lastEvent, modelLine }) }]);
    setChatInput("");
  };

  const runScan = async () => {
    const uri = scanUri.trim();
    if (!uri) return;
    setScanBusy(true); setScanError(""); setScan(null);
    try { setScan(await analyzeRequest(uri)); }
    catch { setScanError("Backend unreachable — the scanner needs the live API (your local stack or the hosted backend)."); }
    setScanBusy(false);
  };
  const sqliEvents = events.filter((e) => e.attack_type === "sqli");
  const incidents = events.filter((e) => e.decision !== "allow");

  const decisionPill = (d) => <span className={`pill-status ${d}`}>{d}</span>;

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <div><strong>ShieldNet</strong><span>AI-Powered WAF</span></div>
        </div>
        <nav>
          {NAV.map(([key, icon, label]) => (
            <button key={key} className={view === key ? "nav-item active" : "nav-item"} onClick={() => setView(key)}>
              <span>{icon}</span>{label}
            </button>
          ))}
        </nav>
        <div className="side-status">
          <div className="brand-icon small">🛡️</div>
          <div>
            <div className="muted small">System Status</div>
            <div className={data.demo ? "status-demo" : "status-ok"}>● {data.demo ? "Demo Mode" : "Operational"}</div>
            <div className="muted small">{data.demo ? "Backend unreachable" : "All layers active"}</div>
          </div>
        </div>
        <p className="tagline">Detect. Analyze. Prevent. Protect.</p>
      </aside>

      <main className="main">
        <div className="topbar">
          <div className="search">
            <span>🔍</span>
            <input placeholder="Search threats, IPs, or patterns..." value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <span className={`pill ${data.demo ? "pill-demo" : "pill-live"}`}>{data.demo ? "DEMO DATA" : "● LIVE"}</span>
          <button className="ghost" onClick={load}>↻ Refresh</button>
          <span className="muted small">{updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : ""}</span>
          <button className="bell" onClick={() => setView("live")} title="Blocked attacks — view live monitoring">
            🔔{(stats.by_decision.block || 0) > 0 && <span className="bell-badge">{stats.by_decision.block}</span>}
          </button>
          <div className="admin-wrap">
            <button className="admin-chip" onClick={() => setMenuOpen((o) => !o)}>
              <span className="avatar">A</span> Admin <span className="muted">▾</span>
            </button>
            {menuOpen && (
              <div className="admin-menu">
                <div className="muted small">Signed in as</div>
                <div className="admin-mail">admin@shieldnet.io</div>
                <button className="logout-btn wide" onClick={onLogout}>⎋ Logout</button>
              </div>
            )}
          </div>
        </div>

        {view === "overview" && (
          <>
            <section className="banner">
              <div className="banner-left">
                <div className="banner-shield">🛡️</div>
                <div>
                  <h1>Welcome to ShieldNet</h1>
                  <p>Your website is protected and secure.</p>
                  <span className="chip-ok">● {data.demo ? "Demo Mode — connect the backend for live protection" : "All Systems Normal"}</span>
                </div>
              </div>
              <div className="globe" aria-hidden="true" />
              <div className="banner-badge">
                🛡️ {data.demo ? "Demo Data Mode" : "Real-Time Protection Active"}
                <span>{updatedAt ? `Last Updated: ${updatedAt.toLocaleDateString()} · ${updatedAt.toLocaleTimeString()}` : `API: ${API_BASE}`}</span>
              </div>
            </section>

            <section className="cards">
              <div className="card"><div className="card-head"><span className="card-ico">🌐</span><div><div className="card-num">{stats.total_requests.toLocaleString()}</div><div className="card-label">Total Requests</div></div>{reqTrend && <span className={`trend ${reqTrend.up ? "up" : "down"}`}>{reqTrend.up ? "↑" : "↓"} {reqTrend.pct}%</span>}</div><Sparkline values={reqBuckets} color="#2f7bff" /></div>
              <div className="card"><div className="card-head"><span className="card-ico red">⚠️</span><div><div className="card-num">{stats.by_decision.block || 0}</div><div className="card-label">Blocked Attacks</div></div>{blockTrend && <span className={`trend ${blockTrend.up ? "up" : "down"}`}>{blockTrend.up ? "↑" : "↓"} {blockTrend.pct}%</span>}</div><Sparkline values={blockBuckets} color="#e5484d" /></div>
              <div className="card"><div className="card-head"><span className="card-ico green">✅</span><div><div className="card-num">{clfBest ? `${(clfBest.f1 * 100).toFixed(1)}%` : "—"}</div><div className="card-label">Model F1 Score *</div></div><span className="trend neutral">synthetic split</span></div><Sparkline values={reqBuckets.map((v, i) => Math.max(0, v - (i % 3)))} color="#30a46c" /></div>
              <div className="card"><div className="card-head"><span className="card-ico purple">⚡</span><div><div className="card-num">{avgRisk.toFixed(1)}</div><div className="card-label">Avg. Risk (recent)</div></div><span className="trend neutral">{detections.length} detections</span></div><Sparkline values={detections.slice(0, 12).map((d) => d.risk_score).reverse()} color="#8e4ec6" /></div>
            </section>
            <p className="muted small footnote">* F1 on the held-out synthetic dataset — a pipeline check, not real-world accuracy. See Threat Detection.</p>

            <section className="grid-2">
              <div className="panel">
                <div className="panel-head"><h2>📈 Threat Analytics</h2>
                  <span className="range-chips">{Object.keys(RANGES).map((r) => <button key={r} className={range === r ? "chip active" : "chip"} onClick={() => setRange(r)}>{r}</button>)}</span>
                  <span className="legend"><i className="dot" style={{ background: "#2f7bff" }} /> Requests <i className="dot" style={{ background: "#e5484d" }} /> Blocked</span></div>
                <AreaChart seriesA={reqBuckets} seriesB={blockBuckets} />
                <p className="muted small">Traffic over the last {range} from the live log feed — wider windows fill in as more history is logged.</p>
              </div>
              <div className="panel">
                <div className="panel-head"><h2>🎯 Attack Distribution</h2></div>
                <ThreatDonut byType={stats.by_attack_type} totalRequests={stats.total_requests} totalDetections={stats.total_detections} />
              </div>
            </section>

            <section className="grid-3">
              <div className="panel">
                <div className="panel-head"><h2>🌍 Global Attack Map</h2></div>
                <div className="map-globe" aria-hidden="true" />
                {topIps.length ? topIps.map(([ip, n]) => (
                  <div className="src-row" key={ip}><span>{ip}</span><span className="muted">{n} requests</span></div>
                )) : <p className="muted">No source data yet</p>}
                <p className="muted small">Origins are tracked by source IP — geolocation lookup isn't enabled in this build, so this panel lists the top sources instead of plotting locations.</p>
              </div>
              <div className="panel wide">
                <div className="panel-head"><h2>🕑 Recent Security Events</h2><button className="link" onClick={() => setView("live")}>View All →</button></div>
                <table className="feed">
                  <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Status</th></tr></thead>
                  <tbody>
                    {events.slice(0, 6).map((e) => (
                      <tr key={e.id}><td>{new Date(e.created_at).toLocaleTimeString()}</td><td>{e.attack_type || "Legitimate Request"}</td><td>{e.ip}</td><td>{decisionPill(e.decision)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="panel assistant">
                <div className="panel-head"><h2>🤖 AI Security Assistant</h2><span className="status-ok small">● Online</span></div>
                <p className="ai-intro">Your security looks {stats.by_decision.block ? "active" : "calm"} 🎉 Here's a quick summary:</p>
                <ul className="ai-summary">{summary.map((s) => <li key={s}>{s}</li>)}</ul>
                <div className="chat-log">
                  {chat.map((m, i) => <div key={i} className={`chat ${m.who}`}>{m.text}</div>)}
                </div>
                <div className="chat-box">
                  <input placeholder="Ask anything about your security..." value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && ask()} />
                  <button onClick={ask}>➤</button>
                </div>
                <p className="muted small">Answers are computed locally from the live stats above — no data leaves your browser.</p>
              </div>
            </section>
          </>
        )}

        {view === "live" && (
          <section className="panel">
            <div className="panel-head"><h2>📊 Live Monitoring — detections</h2></div>
            <table className="feed">
              <thead><tr><th>Time</th><th>Request</th><th>Rule</th><th>ML</th><th>Anomaly</th><th>Risk</th><th>Decision</th><th>Type</th></tr></thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}><td>{new Date(e.created_at).toLocaleTimeString()}</td><td className="uri">{e.uri}</td>
                    <td>{e.rule_score}</td><td>{e.ml_score ?? "—"}</td><td>{e.anomaly_score ?? "—"}</td>
                    <td><strong>{e.risk_score}</strong></td><td>{decisionPill(e.decision)}</td><td>{e.attack_type || "—"}</td></tr>
                ))}
              </tbody>
            </table>
            <div className="panel-head" style={{ marginTop: 18 }}><h2>Request log</h2></div>
            <table className="feed">
              <thead><tr><th>Time</th><th>IP</th><th>Request</th><th>CRS rules</th></tr></thead>
              <tbody>
                {logs.map((l) => (
                  <tr key={l.id}><td>{new Date(l.created_at).toLocaleTimeString()}</td><td>{l.ip || "—"}</td>
                    <td className="uri">{l.method} {l.uri}</td><td>{(l.modsec_rule_ids || []).join(", ") || "—"}</td></tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {view === "threats" && (
          <section className="grid-2">
            <div className="panel">
              <div className="panel-head"><h2>🛡️ Detection models</h2></div>
              {clf ? (
                <table className="feed">
                  <thead><tr><th>Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
                  <tbody>
                    {Object.entries(clf.results || {}).map(([name, r]) => (
                      <tr key={name}><td>{name}{name === clf.best_model ? " ⭐" : ""}</td><td>{r.accuracy}</td><td>{r.precision}</td><td>{r.recall}</td><td>{r.f1}</td></tr>
                    ))}
                  </tbody>
                </table>
              ) : <p className="muted">No classifier metrics loaded.</p>}
              {anom && (
                <table className="kv"><tbody>
                  <tr><td>Anomaly model</td><td>{anom.version} (Isolation Forest)</td></tr>
                  <tr><td>Benign score mean</td><td>{anom.benign_score_mean}</td></tr>
                  <tr><td>Attack score mean</td><td>{anom.attack_score_mean}</td></tr>
                  <tr><td>Attacks scoring &gt; 40</td><td>{(anom.attacks_scoring_over_40 * 100).toFixed(0)}%</td></tr>
                </tbody></table>
              )}
              <p className="muted small">Hybrid weights — rules 0.50 · ML 0.35 · anomaly 0.15, renormalised over loaded signals. Rule ≥ 90 floors risk at 85; ML ≥ 90 floors at monitor.</p>
            </div>
            <div className="panel">
              <div className="panel-head"><h2>🧪 Attack battery — measured results</h2></div>
              <table className="feed">
                <thead><tr><th>Case</th><th>Expected</th></tr></thead>
                <tbody>{BATTERY.map(([name, exp]) => <tr key={name}><td>{name}</td><td>{decisionPill(exp)}</td></tr>)}</tbody>
              </table>
              <p className="muted small">12/12 passing — full measured scores in docs/DEMO.md in the repo.</p>
            </div>
          </section>
        )}

        {view === "intel" && (
          <section className="grid-2">
            <div className="panel">
              <div className="panel-head"><h2>🎯 Attack Intelligence</h2></div>
              <Donut data={stats.by_attack_type} />
            </div>
            <div className="panel">
              <div className="panel-head"><h2>ModSecurity CRS rules triggered</h2></div>
              {(() => {
                const rules = {};
                logs.forEach((l) => (l.modsec_rule_ids || []).forEach((r) => { rules[r] = (rules[r] || 0) + 1; }));
                const rows = Object.entries(rules).sort((a, b) => b[1] - a[1]);
                return rows.length ? (
                  <table className="feed"><thead><tr><th>Rule ID</th><th>Hits</th></tr></thead>
                    <tbody>{rows.map(([r, n]) => <tr key={r}><td>{r}</td><td>{n}</td></tr>)}</tbody></table>
                ) : <p className="muted">No CRS rule hits in the current log window.</p>;
              })()}
            </div>
          </section>
        )}

        {view === "scanner" && (
          <section className="panel">
            <div className="panel-head"><h2>🔍 Website Scanner — test a request against the detection engine</h2></div>
            <p className="muted">Paste any URL or path (with query string). It is scored live by the same hybrid engine — rules + ML + anomaly — that guards the demo shop.</p>
            <div className="scan-box">
              <input value={scanUri} onChange={(e) => setScanUri(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && runScan()}
                placeholder="/search?q=' UNION SELECT username, password FROM users --" />
              <button className="login-btn scan-btn" onClick={runScan} disabled={scanBusy}>{scanBusy ? "Scanning…" : "Scan"}</button>
            </div>
            <div className="scan-samples">
              {["/product?id=2", "/search?q=' UNION SELECT username, password FROM users --", "/comment?text=<script>alert(1)</script>", "/static/../../.env"].map((s) => (
                <button key={s} className="chip" onClick={() => setScanUri(s)}>{s.length > 44 ? s.slice(0, 44) + "…" : s}</button>
              ))}
            </div>
            {scanError && <p className="login-error">{scanError}</p>}
            {scan && (
              <div className="scan-result">
                <div className="scan-risk">
                  <div className="card-num">{Math.round(scan.risk_score)}</div>
                  <div className="card-label">Risk score</div>
                  {decisionPill(scan.decision)}
                </div>
                <table className="kv"><tbody>
                  <tr><td>Attack type</td><td>{scan.attack_type ? (TYPE_LABELS[scan.attack_type] || scan.attack_type) : "—"}</td></tr>
                  <tr><td>Rule score</td><td>{scan.rule_score}</td></tr>
                  <tr><td>ML score</td><td>{scan.ml_score ?? "— (model not loaded on this backend)"}</td></tr>
                  <tr><td>Anomaly score</td><td>{scan.anomaly_score ?? "—"}</td></tr>
                  <tr><td>Model version</td><td>{scan.model_version || "rules-only"}</td></tr>
                </tbody></table>
              </div>
            )}
          </section>
        )}

        {view === "api" && (
          <section className="grid-2">
            <div className="panel">
              <div className="panel-head"><h2>🔌 API Security — requests by method</h2></div>
              <table className="kv"><tbody>
                {Object.entries(logs.reduce((a, l) => { a[l.method] = (a[l.method] || 0) + 1; return a; }, {}))
                  .sort((x, y) => y[1] - x[1])
                  .map(([m, n]) => <tr key={m}><td>{m}</td><td>{n} requests in feed</td></tr>)}
              </tbody></table>
              <p className="muted small">Counts cover the current log feed window ({logs.length} requests). Every request passes the same CRS + hybrid scoring as web traffic.</p>
            </div>
            <div className="panel">
              <div className="panel-head"><h2>Top endpoints</h2></div>
              {(() => {
                const eps = {};
                logs.forEach((l) => { const p = (l.uri || "").split("?")[0]; eps[p] = eps[p] || { n: 0, det: 0 }; eps[p].n += 1; });
                detections.forEach((d) => { const l = logsById[d.request_id]; if (l) { const p = (l.uri || "").split("?")[0]; if (eps[p]) eps[p].det += 1; } });
                const rows = Object.entries(eps).sort((a, b) => b[1].n - a[1].n).slice(0, 8);
                return rows.length ? (
                  <table className="feed"><thead><tr><th>Endpoint</th><th>Requests</th><th>Detections</th></tr></thead>
                    <tbody>{rows.map(([p, v]) => <tr key={p}><td className="uri">{p}</td><td>{v.n}</td><td>{v.det}</td></tr>)}</tbody></table>
                ) : <p className="muted">No requests yet.</p>;
              })()}
            </div>
          </section>
        )}

        {view === "db" && (
          <section className="grid-2">
            <div className="panel">
              <div className="panel-head"><h2>🗄️ Database Guard — SQL injection</h2></div>
              <table className="kv"><tbody>
                <tr><td>SQLi detections</td><td>{sqliEvents.length}</td></tr>
                <tr><td>Blocked</td><td>{sqliEvents.filter((e) => e.decision === "block").length}</td></tr>
                <tr><td>Monitored</td><td>{sqliEvents.filter((e) => e.decision === "monitor").length}</td></tr>
              </tbody></table>
              <p className="muted small">Shielded by the ModSecurity CRS 942xxx SQLi rule family at the WAF, plus the ML classifier and hybrid engine in the backend. Payloads are scored — ShieldNet never executes them against a real database.</p>
            </div>
            <div className="panel">
              <div className="panel-head"><h2>Recent SQLi events</h2></div>
              {sqliEvents.length ? (
                <table className="feed"><thead><tr><th>Time</th><th>Source</th><th>Request</th><th>Risk</th><th>Status</th></tr></thead>
                  <tbody>{sqliEvents.slice(0, 8).map((e) => <tr key={e.id}><td>{new Date(e.created_at).toLocaleTimeString()}</td><td>{e.ip}</td><td className="uri">{e.uri}</td><td>{e.risk_score}</td><td>{decisionPill(e.decision)}</td></tr>)}</tbody></table>
              ) : <p className="muted">No SQL injection attempts recorded yet.</p>}
            </div>
          </section>
        )}

        {view === "assistant" && (
          <section className="panel assistant">
            <div className="panel-head"><h2>🤖 AI Security Assistant</h2><span className="status-ok small">● Online</span></div>
            <p className="ai-intro">Your security looks {stats.by_decision.block ? "active" : "calm"} 🎉 Here's a quick summary:</p>
            <ul className="ai-summary">{summary.map((s) => <li key={s}>{s}</li>)}</ul>
            <div className="chat-log">
              {chat.map((m, i) => <div key={i} className={`chat ${m.who}`}>{m.text}</div>)}
            </div>
            <div className="chat-box">
              <input placeholder="Ask anything about your security..." value={chatInput}
                onChange={(e) => setChatInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && ask()} />
              <button onClick={ask}>➤</button>
            </div>
            <p className="muted small">Answers are computed locally from the live stats above — no data leaves your browser.</p>
          </section>
        )}

        {view === "incidents" && (
          <section className="grid-2">
            <div className="panel">
              <div className="panel-head"><h2>🚨 Incident Response</h2></div>
              {incidents.length ? (
                <table className="feed"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Risk</th><th>Decision</th><th>Status</th><th></th></tr></thead>
                  <tbody>{incidents.map((e) => (
                    <tr key={e.id}><td>{new Date(e.created_at).toLocaleTimeString()}</td><td>{e.attack_type || "—"}</td><td>{e.ip}</td>
                      <td>{e.risk_score}</td><td>{decisionPill(e.decision)}</td>
                      <td>{acked[e.id] ? <span className="pill-status monitor">acknowledged</span> : <span className="pill-status block">open</span>}</td>
                      <td>{!acked[e.id] && <button className="link" onClick={() => setAcked((a) => ({ ...a, [e.id]: true }))}>Acknowledge</button>}</td></tr>
                  ))}</tbody></table>
              ) : <p className="muted">No incidents — nothing has been blocked or flagged yet.</p>}
              <p className="muted small">Acknowledgements are kept in this browser session only.</p>
            </div>
            <div className="panel">
              <div className="panel-head"><h2>Response playbook</h2></div>
              <ol className="playbook">
                <li><strong>Verify</strong> — open the event in Live Monitoring; check the payload and source IP.</li>
                <li><strong>Contain</strong> — blocked decisions are already enforced by the WAF; for monitored events, watch for repeats from the same source.</li>
                <li><strong>Tune</strong> — repeated false positives? Note the CRS rule ID in Attack Intelligence and review it before touching thresholds.</li>
                <li><strong>Record</strong> — export a report from Reports, then acknowledge the incident here.</li>
              </ol>
            </div>
          </section>
        )}

        {view === "reports" && (
          <section className="panel">
            <div className="panel-head"><h2>📄 Reports</h2>
              <button className="ghost" onClick={() => {
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob); a.download = "shieldnet-report.json"; a.click();
              }}>⬇ Export JSON</button>
            </div>
            <table className="kv"><tbody>
              <tr><td>Total requests</td><td>{stats.total_requests}</td></tr>
              <tr><td>Analyzed</td><td>{stats.total_detections}</td></tr>
              <tr><td>Allowed / Monitored / Blocked</td><td>{stats.by_decision.allow || 0} / {stats.by_decision.monitor || 0} / {stats.by_decision.block || 0}</td></tr>
              <tr><td>Attack types seen</td><td>{Object.keys(stats.by_attack_type).join(", ") || "none"}</td></tr>
              <tr><td>Data source</td><td>{data.demo ? "Demo data (backend unreachable)" : `Live — ${API_BASE}`}</td></tr>
            </tbody></table>
          </section>
        )}

        {view === "settings" && (
          <section className="panel">
            <div className="panel-head"><h2>⚙️ Settings</h2></div>
            <table className="kv"><tbody>
              <tr><td>Backend API</td><td>{API_BASE} (set via VITE_API_BASE_URL)</td></tr>
              <tr><td>Auto-refresh</td><td>Every 10 seconds</td></tr>
              <tr><td>Decision thresholds</td><td>Monitor ≥ 40 · Block ≥ 75 (backend env)</td></tr>
              <tr><td>WAF mode</td><td>ModSecurity CRS — see docs/DEPLOYMENT_LIFECYCLE.md for learning → blocking rollout</td></tr>
            </tbody></table>
          </section>
        )}

        <footer className="muted small">ShieldNet — ModSecurity CRS + XGBoost/Random Forest + Isolation Forest, combined by a hybrid scoring engine. Detect. Analyze. Prevent. Protect.</footer>
      </main>
    </div>
  );
}

/* ---------- Login ----------
   Real backend auth: POST /auth/login verifies the password (Argon2id hash)
   and issues a JWT access token + httpOnly refresh cookie; the API itself
   rejects unauthenticated calls. The demo account below is a seeded user in
   the backend database. If the backend is unreachable, the same credentials
   enter the offline demo-data mode so the console can still be explored. */
const DEMO_ACCOUNT = { email: "admin@shieldnet.io", password: "shieldnet" };

function Login({ onLogin, onDemoLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await apiLogin(email.trim().toLowerCase(), password);
      onLogin();
    } catch (err) {
      if (err.status === 401) {
        setError("Invalid email or password — use the demo credentials below.");
      } else if (err.status === 429) {
        setError("Too many failed attempts — wait a few minutes and try again.");
      } else if (email.trim().toLowerCase() === DEMO_ACCOUNT.email && password === DEMO_ACCOUNT.password) {
        onDemoLogin(); // backend unreachable: offline demo-data mode
      } else {
        setError("Backend unreachable — check your connection, or use the demo credentials for offline demo mode.");
      }
    }
    setBusy(false);
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <div><strong>ShieldNet</strong><span>AI-Powered WAF</span></div>
        </div>
        <h1>Sign in to the console</h1>
        <p className="muted">Monitor threats, detections and WAF activity in real time.</p>
        <label className="login-label">Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
            placeholder="admin@shieldnet.io" autoFocus required />
        </label>
        <label className="login-label">Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••" required />
        </label>
        {error && <p className="login-error">{error}</p>}
        <button className="login-btn" type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign In →"}</button>
        <div className="login-hint">
          Demo account — email <code>admin@shieldnet.io</code> · password <code>shieldnet</code>
        </div>
        <p className="muted small">Sign-in is verified by the ShieldNet backend — passwords are Argon2id-hashed and the API requires a JWT. If the backend is offline, the demo account opens the console in demo-data mode.</p>
      </form>
    </div>
  );
}

export default function App() {
  // "checking" while we try to restore the session from the refresh cookie.
  const [authState, setAuthState] = useState("checking");
  const [demoSession, setDemoSession] = useState(false);

  useEffect(() => {
    refreshSession().then((ok) => setAuthState(ok ? "in" : "out"));
  }, []);

  if (authState === "checking" && !demoSession) {
    return <div className="boot">Loading ShieldNet console…</div>;
  }
  if (authState !== "in" && !demoSession) {
    return (
      <Login
        onLogin={() => setAuthState("in")}
        onDemoLogin={() => setDemoSession(true)}
      />
    );
  }
  return (
    <Dashboard
      onLogout={async () => {
        await apiLogout();
        setDemoSession(false);
        setAuthState("out");
      }}
    />
  );
}
