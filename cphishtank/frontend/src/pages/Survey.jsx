import { useEffect, useState } from "react";
import { api } from "../api";

const YN = [["true", "Yes"], ["false", "No"]];
const LIKERT = ["Strongly disagree", "Disagree", "Neutral", "Agree", "Strongly agree"];

function Likert({ name, value, onChange }) {
  return (
    <div className="likert" role="radiogroup">
      {LIKERT.map((l, i) => (
        <label key={l} className={String(value) === String(i + 1) ? "on" : ""}>
          <input type="radio" name={name} value={i + 1} checked={String(value) === String(i + 1)} onChange={(e) => onChange(e.target.value)} />{l}
        </label>))}
    </div>);
}

export default function Survey() {
  const [q, setQ] = useState(null);
  const [f, setF] = useState({ quiz: {} });
  const [res, setRes] = useState(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { api.surveyQuestions().then(setQ).catch((e) => setErr(e.message)); }, []);
  const set = (k) => (e) => setF({ ...f, [k]: e.target ? e.target.value : e });
  const bool = (v) => (v === "true" ? true : v === "false" ? false : null);

  async function submit(e) {
    e.preventDefault(); setBusy(true); setErr("");
    try {
      setRes(await api.surveySubmit({
        age_group: f.age_group || null, occupation: f.occupation || null, tech_level: f.tech_level ? +f.tech_level : null,
        received_phishing: bool(f.received), fell_for_it: bool(f.fell), reports_phishing: bool(f.reports),
        trust_ai: f.trust ? +f.trust : null, would_adopt: f.adopt ? +f.adopt : null, comments: f.comments || null, quiz_answers: f.quiz,
      }));
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (x) { setErr(x.message); } finally { setBusy(false); }
  }

  if (res) return (
    <div className="page narrow">
      <h1>Thank you. You got {res.quiz_score} of {res.quiz_total} right.</h1>
      <p className="muted">Your answers are stored without your name or email in the survey data.</p>
      <ul className="quiz-review">
        {q?.quiz.map((m) => { const r = res.answers.find((a) => a.id === m.id); return (
          <li key={m.id} className={r.correct ? "right" : "wrong"}>
            <p className="sheet-body">{m.text}</p>
            <b>{r.correct ? "Correct" : "Not quite"}: this one is {r.answer === "phishing" ? "phishing" : "legitimate"}.</b>
          </li>); })}
      </ul>
    </div>);

  return (
    <div className="page narrow">
      <h1>Phishing awareness survey</h1>
      <p>Two minutes, anonymous. It helps us study how people spot phishing and how much they'd trust AI tools to help.</p>
      {err && <p className="error" role="alert">{err}</p>}
      {q && (
        <form className="survey" onSubmit={submit}>
          <fieldset><legend>About you</legend>
            <label>Age group<select value={f.age_group || ""} onChange={set("age_group")}><option value="">Prefer not to say</option>{q.choices.age_group.map((a) => <option key={a}>{a}</option>)}</select></label>
            <label>Field<select value={f.occupation || ""} onChange={set("occupation")}><option value="">Prefer not to say</option>{q.choices.occupation.map((a) => <option key={a}>{a}</option>)}</select></label>
            <label>How comfortable are you with technology? <span className="muted">1 = beginner, 5 = expert</span>
              <select value={f.tech_level || ""} onChange={set("tech_level")}><option value="">Select</option>{[1, 2, 3, 4, 5].map((n) => <option key={n}>{n}</option>)}</select></label>
          </fieldset>

          <fieldset><legend>Your experience</legend>
            {[["received", "Have you received a phishing email or text?"], ["fell", "Have you ever clicked or entered details on one?"], ["reports", "Do you usually report phishing messages?"]].map(([k, label]) => (
              <div key={k} className="qrow"><span>{label}</span>
                <div className="seg small">{YN.map(([v, l]) => <label key={v} className={f[k] === v ? "on" : ""}><input type="radio" name={k} value={v} checked={f[k] === v} onChange={set(k)} />{l}</label>)}</div></div>))}
          </fieldset>

          <fieldset><legend>Can you spot it?</legend>
            <p className="muted">Mark each message as phishing or legitimate.</p>
            {q.quiz.map((m) => (
              <div key={m.id} className="qrow stack"><p className="sheet-body">{m.text}</p>
                <div className="seg small">{["phishing", "legitimate"].map((v) => (
                  <label key={v} className={f.quiz[m.id] === v ? "on" : ""}><input type="radio" name={m.id} checked={f.quiz[m.id] === v}
                    onChange={() => setF({ ...f, quiz: { ...f.quiz, [m.id]: v } })} />{v === "phishing" ? "Phishing" : "Legitimate"}</label>))}</div></div>))}
          </fieldset>

          <fieldset><legend>AI security tools</legend>
            <div className="qrow stack"><span>I would trust an AI tool's verdict on whether a message is a scam.</span><Likert name="trust" value={f.trust} onChange={(v) => setF({ ...f, trust: v })} /></div>
            <div className="qrow stack"><span>I would use a tool like this regularly if it explained its reasoning.</span><Likert name="adopt" value={f.adopt} onChange={(v) => setF({ ...f, adopt: v })} /></div>
            <label>Anything else? <span className="muted">(optional)</span><textarea rows={3} maxLength={2000} value={f.comments || ""} onChange={set("comments")} /></label>
          </fieldset>
          <button className="btn" disabled={busy}>{busy ? "Sending…" : "Submit survey"}</button>
        </form>)}
    </div>
  );
}
