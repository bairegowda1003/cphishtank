import { useEffect, useState } from "react";
import { api } from "../api";
import { Columns, DailyBars, HBars, LabelDonut } from "../components/Charts";

function LabeledMessageCapture() {
  const [text, setText] = useState(""); const [label, setLabel] = useState("safe");
  const [channel, setChannel] = useState("email"); const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setStatus("");
    try {
      const result = await api.addLabeledMessage({ text, label, channel, confirmed_own_inbox: confirmed });
      setText(""); setConfirmed(false);
      setStatus(result.status === "duplicate" ? "This cleaned message was already recorded." : "Sanitized message added for the next training run.");
    } catch (e) { setStatus(e.message); }
    finally { setBusy(false); }
  }
  return (
    <section className="panel" aria-labelledby="capture-title">
      <h2 id="capture-title">Add a message for training</h2>
      <p>Only add messages from your own inbox that you are allowed to use. Remove secrets and personal details first. The server masks common email addresses and phone numbers, strips URL query strings, and stores only cleaned text; it does not log the pasted content.</p>
      <form className="survey" onSubmit={submit}>
        <label>Message<textarea required minLength={12} maxLength={20000} rows={8} value={text}
          onChange={(e) => setText(e.target.value)} placeholder="Paste an email or SMS, including headers if useful." /></label>
        <div className="row two-col">
          <label>Label<select value={label} onChange={(e) => setLabel(e.target.value)}>
            <option value="safe">Safe / legitimate</option><option value="scam">Scam / phishing</option>
          </select></label>
          <label>Channel<select value={channel} onChange={(e) => setChannel(e.target.value)}>
            <option value="email">Email</option><option value="sms">SMS</option>
          </select></label>
        </div>
        <label className="check"><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          I confirm this is from my own inbox, I have permission to use it, and I removed sensitive details.</label>
        <div className="row actions"><button className="btn" disabled={busy || !confirmed || !text.trim()}>{busy ? "Saving…" : "Save cleaned example"}</button></div>
        {status && <p role="status" className={status.startsWith("Sanitized") || status.startsWith("This cleaned") ? "muted" : "error"}>{status}</p>}
      </form>
    </section>
  );
}

export default function Admin() {
  const [o, setO] = useState(null); const [sv, setSv] = useState(null); const [err, setErr] = useState("");
  useEffect(() => {
    api.adminOverview().then(setO).catch((e) => setErr(e.message));
    api.surveyStats().then(setSv).catch((e) => setErr(e.message));
  }, []);
  if (err) return <div className="page"><p className="error">{err}</p></div>;
  if (!o) return <div className="page"><p className="muted">Loading…</p></div>;
  const m = o.model;
  return (
    <div className="page wide">
      <h1>Threat overview</h1>
      <LabeledMessageCapture />
      <div className="stats">
        <div className="stat"><b>{o.totals.scans}</b><span>messages scanned</span></div>
        <div className="stat"><b>{o.totals.flagged}</b><span>flagged as risky</span></div>
        <div className="stat"><b>{o.totals.users}</b><span>registered users</span></div>
        <div className="stat"><b>{o.totals.surveys}</b><span>survey responses</span></div>
      </div>

      <div className="grid3">
        <div className="panel"><h3>Verdicts</h3><div className="chart sm"><LabelDonut labels={o.labels} /></div></div>
        <div className="panel span2"><h3>Scans per day</h3><div className="chart sm"><DailyBars daily={o.daily} /></div></div>
      </div>
      <div className="two">
        <div className="panel"><h3>Most common phishing patterns</h3><div className="chart"><HBars items={o.top_signals} /></div></div>
        <div className="panel"><h3>Most reported risky domains</h3>
          {o.top_domains.length === 0 ? <p className="muted">No risky domains recorded yet.</p> : (
            <table><thead><tr><th>Domain</th><th>Seen</th><th>Avg risk</th></tr></thead>
              <tbody>{o.top_domains.map((d) => <tr key={d.domain}><td className="mono">{d.domain}</td><td>{d.count}</td><td>{d.avg_risk}</td></tr>)}</tbody></table>)}
        </div>
      </div>
      <div className="two">
        <div className="panel"><h3>Risk score distribution</h3>
          <div className="chart sm"><Columns labels={["0-9", "10-19", "20-29", "30-39", "40-49", "50-59", "60-69", "70-79", "80-89", "90+"]} data={o.risk_histogram} name="Scans" /></div></div>
        <div className="panel"><h3>Model and feedback</h3>
          <dl className="kv">
            <dt>Algorithm</dt><dd>{m.algorithm || "Not trained"}</dd>
            <dt>Trained on</dt><dd>{m.samples?.toLocaleString() ?? "–"} messages {m.uses_real_data ? "(real, cleaned datasets)" : "(synthetic starter data, not representative)"}</dd>
            <dt>Accuracy</dt><dd>{m.accuracy != null ? `${(m.accuracy * 100).toFixed(1)}%` : "–"} (macro-F1 {m.macro_f1 ?? "–"}) on a {m.evaluation || "held-out split"}</dd>
            <dt>New phishing caught</dt><dd>{m.newest_phishing_recall != null ? `${(m.newest_phishing_recall * 100).toFixed(0)}% of the newest emails the model had never seen` : "–"}</dd>
            <dt>False alarms</dt><dd>{m.false_positive_rate != null ? `${(m.false_positive_rate * 100).toFixed(1)}% of legitimate messages` : "–"}</dd>
            <dt>User agreement</dt><dd>{o.feedback.agreement_pct != null ? `${o.feedback.agreement_pct}% of ${o.feedback.correct + o.feedback.incorrect} rated verdicts` : "No ratings yet"}</dd>
          </dl>
        </div>
      </div>

      <h2>Survey findings</h2>
      {!sv || !sv.n ? <p className="empty">No survey responses yet.</p> : (<>
        <div className="stats">
          <div className="stat"><b>{sv.quiz_mean_pct}%</b><span>average quiz score (SD {sv.quiz_sd_pct})</span></div>
          <div className="stat"><b>{sv.pct_fell_for_it}%</b><span>have fallen for phishing</span></div>
          <div className="stat"><b>{sv.trust_ai_mean ?? "–"}</b><span>trust in AI verdicts (1-5)</span></div>
          <div className="stat"><b>{sv.would_adopt_mean ?? "–"}</b><span>would adopt (1-5)</span></div>
        </div>
        <div className="two">
          <div className="panel"><h3>Trust in AI verdicts</h3><div className="chart sm"><Columns labels={["1", "2", "3", "4", "5"]} data={sv.likert_trust} color="#177E5A" /></div></div>
          <div className="panel"><h3>Quiz scores</h3><div className="chart sm"><Columns labels={sv.quiz_hist.map((_, i) => String(i))} data={sv.quiz_hist} color="#D62839" name="People" /></div></div>
        </div>
        <div className="panel"><h3>Statistical tests (n = {sv.n})</h3>
          {sv.tests.length === 0 ? <p className="muted">Not enough varied responses yet. Tests appear once there are about five or more answers.</p> : (
            <table><thead><tr><th>Test</th><th>Statistic</th><th>p-value</th><th>n</th><th>Reading</th></tr></thead>
              <tbody>{sv.tests.map((t) => <tr key={t.name}><td>{t.name}</td><td>{t.stat}</td><td>{t.p}</td><td>{t.n}</td><td>{t.reading}</td></tr>)}</tbody></table>)}
        </div>
      </>)}
    </div>
  );
}
