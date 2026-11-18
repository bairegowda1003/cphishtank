import { useState } from "react";
import { api } from "../api";

const LABELS = {
  legitimate: { name: "Looks legitimate", cls: "ok" },
  suspicious: { name: "Suspicious", cls: "warn" },
  phishing: { name: "Likely phishing", cls: "bad" },
};
const KIND_NOTE = {
  credential: "Asks for sensitive data", url_bad: "Dangerous link", urgency: "Pressure / urgency",
  money: "Money or prize bait", url_warn: "Questionable link", greeting: "Generic greeting",
  attachment: "Attachment bait", ml: "Phishing-style wording",
};

export function RiskRing({ score, verdict }) {
  const circumference = 2 * Math.PI * 52;
  const value = Math.min(100, Math.max(0, Number(score) || 0));
  return (
    <div className="risk-ring-wrap">
      <div className={`risk-ring ${verdict}`} role="img" aria-label={`Risk score ${Math.round(value)} out of 100`}>
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle className="risk-ring-track" cx="60" cy="60" r="52" />
          <circle className="risk-ring-value" cx="60" cy="60" r="52" strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - value / 100)} />
        </svg>
        <div className="risk-ring-center"><strong>{Math.round(value)}</strong><span>RISK SCORE</span></div>
      </div>
    </div>
  );
}

function VerdictIcon({ verdict }) {
  if (verdict === "ok") return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6" /></svg>;
  if (verdict === "warn") return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 10 18H2L12 3Z" /><path d="M12 9v5m0 3h.01" /></svg>;
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5 20 6v5.2c0 5.2-3.4 8.6-8 10.3-4.6-1.7-8-5.1-8-10.3V6l8-3.5Z" /><path d="m9 9 6 6m0-6-6 6" /></svg>;
}

export function Highlighted({ text, spans }) {
  const out = []; let pos = 0;
  (spans || []).forEach((s, i) => {
    if (s.start < pos) return;
    if (s.start > pos) out.push(text.slice(pos, s.start));
    out.push(<mark key={i} className={`m-${s.kind}`} title={s.reason}>{text.slice(s.start, s.end)}</mark>);
    pos = s.end;
  });
  out.push(text.slice(pos));
  return <>{out}</>;
}

export default function ResultView({ r }) {
  const [fb, setFb] = useState(r.user_feedback || null);
  const L = LABELS[r.label];
  const kinds = [...new Set((r.highlights || []).map((h) => h.kind))];
  const sendFb = async (v) => { setFb(v); if (r.id) try { await api.feedback(r.id, v); } catch { /* ignore */ } };

  return (
    <section className="result" aria-live="polite">
      <div className="result-grid">
        <article className="sheet" aria-label="Your message with suspicious parts marked">
          <div className="sheet-head">
            {r.sender?.raw && <div><span className="k">From</span> {r.sender.raw}</div>}
            {r.reply_to && <div><span className="k">Reply-To</span> {r.reply_to}</div>}
            {r.subject && <div><span className="k">Subject</span> {r.subject}</div>}
            {!r.sender?.raw && !r.subject && <div className="muted">{r.channel === "sms" ? "Text message" : "Pasted message"}</div>}
          </div>
          <p className="sheet-body"><Highlighted text={r.text} spans={r.highlights} /></p>
          {kinds.length > 0 && (
            <ul className="legend" aria-label="Marker key">
              {kinds.map((k) => <li key={k}><mark className={`m-${k}`}>{KIND_NOTE[k]}</mark></li>)}
            </ul>
          )}
        </article>

        <div className="verdict-col">
          <div className={`verdict ${L.cls}`}>
            <h2 className="verdict-title"><span className="verdict-icon"><VerdictIcon verdict={L.cls} /></span>{L.name}</h2>
            <RiskRing score={r.risk_score} verdict={L.cls} />
            <p>{r.summary}</p>
          </div>
          {r.reassurance?.length > 0 && (
            <ul className="reassure" aria-label="Reassuring signs">{r.reassurance.map((t, i) => <li key={i}>{t}</li>)}</ul>)}
          <div className="mini-scores muted">
            <span>Language model: <b>{Math.round(r.scores.ml_risk)}</b></span>
            <span>Rule checks: <b>{Math.round(r.scores.heuristic_risk)}</b></span>
          </div>
        </div>
      </div>

      <div className="two">
        <div className="panel">
          <h3>Why it was flagged</h3>
          {r.signals.length === 0 ? <p className="muted">No red flags found in the sender, links or wording.</p> : (
            <ul className="reasons">
              {r.signals.map((s, i) => (
                <li key={i} className={`sev-${s.severity}`}>
                  <b>{s.title}</b>
                  <p>{s.detail}</p>
                  {s.evidence && <code>{s.evidence}</code>}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="panel">
          <h3>What to do</h3>
          <ul className="advice">{r.advice.map((a, i) => <li key={i}>{a}</li>)}</ul>
          {(r.explanation?.toward_phishing?.length > 0) && (<>
            <h3 className="sp">Words that moved the model</h3>
            <p className="muted small-t">Contribution of each word or phrase to the language model's decision.</p>
            <ul className="bars">
              {r.explanation.toward_phishing.map((t) => (
                <li key={t.term}><span>{t.term}</span><i style={{ width: `${Math.min(100, t.weight * 40)}%` }} /></li>
              ))}
              {r.explanation.toward_legitimate.map((t) => (
                <li key={t.term} className="neg"><span>{t.term}</span><i style={{ width: `${Math.min(100, -t.weight * 40)}%` }} /></li>
              ))}
            </ul>
            <p className="muted small-t">Red bars push toward phishing, green bars toward legitimate.</p>
          </>)}
        </div>
      </div>

      {r.urls.length > 0 && (
        <div className="panel">
          <h3>Links found ({r.urls.length})</h3>
          <div className="scroll"><table>
            <thead><tr><th>Link</th><th>Domain</th><th>Risk</th><th>Findings</th></tr></thead>
            <tbody>{r.urls.map((u, i) => (
              <tr key={i}>
                <td className="mono wrap">{u.url}</td><td className="mono">{u.domain}</td>
                <td><span className={`pill ${u.risk >= 60 ? "bad" : u.risk >= 25 ? "warn" : "ok"}`}>{Math.round(u.risk)}</span></td>
                <td>{u.signals.length ? u.signals.map((s) => s.title).join("; ") : "Nothing unusual"}</td>
              </tr>))}</tbody>
          </table></div>
          <p className="muted small-t">Never open these links to "check" them. Use the findings above instead.</p>
        </div>
      )}

      <div className="fb">
        <span>Was this verdict right?</span>
        <button className={`chip ${fb === "correct" ? "on" : ""}`} onClick={() => sendFb("correct")}>Yes</button>
        <button className={`chip ${fb === "incorrect" ? "on" : ""}`} onClick={() => sendFb("incorrect")}>No</button>
        {fb && <span className="muted">Thanks, this helps improve the checks.</span>}
      </div>
    </section>
  );
}
