import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import AuthLayout from "../components/AuthLayout";

export default function ForgotPassword() {
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api.forgotPassword({ email });
      nav("/reset-password", { state: { email, message: result.message } });
    } catch (issue) {
      setError(issue.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Account recovery"
      title="Forgot your password?"
      description="We'll send a one-time code if an account matches that email."
      footer={<p>Remembered it? <Link to="/login">Back to sign in</Link></p>}
    >
      <form className="auth-form" onSubmit={submit}>
        <label className="auth-label" htmlFor="forgot-email">
          Email address
          <input id="forgot-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)}
            autoComplete="email" required maxLength={254} />
        </label>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn auth-submit" disabled={busy}>
          {busy && <i className="spinner" aria-hidden="true" />}
          {busy ? "Sending…" : "Send recovery code"}
        </button>
      </form>
    </AuthLayout>
  );
}
