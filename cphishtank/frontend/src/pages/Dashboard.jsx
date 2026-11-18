import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { DailyBars, HBars, LabelDonut } from "../components/Charts";

export default function Dashboard() {
  const [s, setS] = useState(null); const [err, setErr] = useState("");
  useEffect(() => { api.myStats().then(setS).catch((e) => setErr(e.message)); }, []);
  if (err) return <div className="page"><p className="error">{err}</p></div>;
  if (!s) return <div className="page"><p className="muted">Loading…</p></div>;
  if (!s.total) return <div className="page"><h1>My dashboard</h1><p className="empty">No scans yet. <Link to="/">Check a message</Link> to start building your dashboard.</p></div>;
  return (
    <div className="page">
      <h1>My dashboard</h1>
      <div className="stats">
        <div className="stat"><b>{s.threats_caught}</b><span>threats caught</span></div>
        <div className="stat"><b>{s.total}</b><span>messages checked</span></div>
        <div className="stat"><b>{s.labels.phishing}</b><span>confirmed phishing</span></div>
        <div className="stat"><b>{s.avg_risk}</b><span>average risk score</span></div>
      </div>
      <div className="two">
        <div className="panel"><h3>Verdict mix</h3><div className="chart sm"><LabelDonut labels={s.labels} /></div></div>
        <div className="panel"><h3>Red flags you meet most</h3><div className="chart sm"><HBars items={s.top_red_flags} /></div></div>
      </div>
      <div className="panel"><h3>Last 30 days</h3><div className="chart"><DailyBars daily={s.daily} /></div></div>
    </div>
  );
}
