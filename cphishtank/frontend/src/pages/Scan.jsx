import { useRef, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import ResultView from "../components/ResultView";

const SAMPLES = {
  "Bank KYC text": { channel: "sms", sender: "", subject: "", text: "SBI: Your KYC has expired and your account will be blocked today. Update PAN immediately: https://bit.ly/3xK42z" },
  "Fake PayPal email": { channel: "email", sender: "PayPal Support <help@paypa1-alerts.com>", subject: "Urgent: your account is limited",
    text: "Dear customer,\n\nWe detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your password.\n\nVerify now: http://paypa1-secure-login.com/verify\n\nPayPal Security Team" },
  "Normal work email": { channel: "email", sender: "Rahul Mehta <rahul@acme-corp.com>", subject: "Project report", text: "Hi Priya, are we still meeting at 3pm tomorrow to go through the project report? I've put the draft in the team folder. Thanks, Rahul" },
};

export default function Scan() {
  const { user } = useAuth();
  const [form, setForm] = useState({ channel: "email", sender: "", subject: "", text: "", save: true });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState(null);
  const file = useRef();
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });

  async function run(fn) {
    setBusy(true); setErr("");
    try { setRes(await fn()); setTimeout(() => document.getElementById("result-anchor")?.scrollIntoView({ behavior: "smooth" }), 50); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  }
  const submit = (e) => { e.preventDefault(); run(() => api.scan({ ...form, sender: form.sender || null, subject: form.subject || null })); };
  const upload = (e) => { const f = e.target.files[0]; if (f) run(() => api.upload(f, form.channel, form.save)); e.target.value = ""; };

  return (
    <div className="page">
      <section className="intro">
        <h1>Is this message safe to trust?</h1>
        <p>Paste an email or text message. You'll get a risk score and the exact words, links and sender details that raised suspicion.</p>
      </section>

      <form className="desk" onSubmit={submit}>
        <div className="row">
          <div className="seg" role="radiogroup" aria-label="Message type">
            {["email", "sms"].map((c) => (
              <label key={c} className={form.channel === c ? "on" : ""}>
                <input type="radio" name="channel" checked={form.channel === c} onChange={() => setForm({ ...form, channel: c })} />{c === "email" ? "Email" : "Text message"}
              </label>))}
          </div>
          <div className="samples"><span className="muted">Try an example:</span>
            {Object.entries(SAMPLES).map(([k, v]) => <button type="button" className="link" key={k} onClick={() => setForm({ ...form, ...v })}>{k}</button>)}
          </div>
        </div>
        <div className="row two-col">
          <label>Sender <span className="muted">(optional)</span><input value={form.sender} onChange={set("sender")} placeholder={form.channel === "sms" ? "Phone number or sender name" : "Name <address@domain.com>"} /></label>
          {form.channel === "email" && <label>Subject <span className="muted">(optional)</span><input value={form.subject} onChange={set("subject")} /></label>}
        </div>
        <label>Message
          <textarea rows={8} value={form.text} onChange={set("text")} required minLength={3} placeholder="Paste the message here. Pasted headers (From:, Subject:, Reply-To:) are picked up automatically." />
        </label>
        <div className="row actions">
          <button className="btn" disabled={busy || form.text.trim().length < 3}>{busy ? "Checking…" : "Check message"}</button>
          <button type="button" className="btn ghost" onClick={() => file.current.click()} disabled={busy}>Upload .eml or .txt</button>
          <input ref={file} type="file" accept=".eml,.txt" hidden onChange={upload} />
          <label className="check"><input type="checkbox" checked={form.save} onChange={set("save")} />Save to {user ? "my history" : "anonymous statistics"}</label>
        </div>
        {err && <p className="error" role="alert">{err}</p>}
      </form>

      <div id="result-anchor" />
      {res && <ResultView r={res} key={res.id ?? res.text} />}
    </div>
  );
}
