import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import ResultView from "../components/ResultView";

export default function History() {
  const { id } = useParams();
  const nav = useNavigate();
  const [data, setData] = useState(null);
  const [filter, setFilter] = useState("");
  const [detail, setDetail] = useState(null);
  const [err, setErr] = useState("");

  const load = () => api.scans(`?limit=50${filter ? `&label=${filter}` : ""}`).then(setData).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [filter]);
  useEffect(() => { setDetail(null); if (id) api.scan_get(id).then(setDetail).catch((e) => setErr(e.message)); }, [id]);

  const remove = async (sid) => { if (confirm("Delete this scan from your history?")) { await api.scan_delete(sid); if (String(sid) === id) nav("/history"); load(); } };

  if (id) return (
    <div className="page">
      <Link to="/history" className="link">← Back to history</Link>
      {err && <p className="error">{err}</p>}
      {detail ? <ResultView r={detail} key={detail.id} /> : !err && <p className="muted">Loading…</p>}
    </div>);

  return (
    <div className="page">
      <h1>Scan history</h1>
      <div className="seg small" role="radiogroup" aria-label="Filter by verdict">
        {[["", "All"], ["phishing", "Phishing"], ["suspicious", "Suspicious"], ["legitimate", "Legitimate"]].map(([v, l]) => (
          <label key={v} className={filter === v ? "on" : ""}><input type="radio" checked={filter === v} onChange={() => setFilter(v)} />{l}</label>))}
      </div>
      {err && <p className="error">{err}</p>}
      {!data ? <p className="muted">Loading…</p> : data.items.length === 0 ? (
        <p className="empty">Nothing here yet. <Link to="/">Check your first message</Link> and it will show up here.</p>
      ) : (
        <div className="scroll"><table className="hist">
          <thead><tr><th>When</th><th>Verdict</th><th>Risk</th><th>Message</th><th /></tr></thead>
          <tbody>{data.items.map((s) => (
            <tr key={s.id}>
              <td className="nowrap">{new Date(s.created_at + "Z").toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}</td>
              <td><span className={`pill ${s.label === "phishing" ? "bad" : s.label === "suspicious" ? "warn" : "ok"}`}>{s.label}</span></td>
              <td>{Math.round(s.risk_score)}</td>
              <td className="wrap"><Link to={`/history/${s.id}`}>{s.subject || s.preview || "(no text)"}</Link><div className="muted small-t">{s.sender || (s.channel === "sms" ? "Text message" : "")}</div></td>
              <td><button className="link" onClick={() => remove(s.id)}>Delete</button></td>
            </tr>))}</tbody>
        </table></div>)}
    </div>
  );
}
