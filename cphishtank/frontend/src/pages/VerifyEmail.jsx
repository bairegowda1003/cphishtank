import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import AuthLayout from "../components/AuthLayout";
import OtpInput from "../components/OtpInput";

export default function VerifyEmail() {
  const location = useLocation();
  const nav = useNavigate();
  const [email, setEmail] = useState(location.state?.email || "");
  const [code, setCode] = useState("");
  const [seconds, setSeconds] = useState(60);
  const [message, setMessage] = useState(location.state?.message || "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resending, setResending] = useState(false);

  useEffect(() => {
    if (seconds <= 0) return undefined;
    const timer = window.setTimeout(() => setSeconds((value) => value - 1), 1000);
    return () => window.clearTimeout(timer);
  }, [seconds]);

  async function submit(event) {
    event.preventDefault();
    if (code.length !== 6) return setError("Enter all 6 digits.");
    setBusy(true);
    setError("");
    try {
      await api.verifyEmail({ email, otp: code });
      nav("/login", { replace: true, state: { email, message: "Email verified. Sign in to continue." } });
    } catch (issue) {
      setError(issue.message);
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    setResending(true);
    setError("");
    setMessage("");
    try {
      const result = await api.resendOtp({ email, purpose: "verify" });
      setMessage(result.message);
      setSeconds(60);
    } catch (issue) {
      setError(issue.message);
    } finally {
      setResending(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Email verification"
      title="Check your inbox"
      description="Enter the 6-digit code we sent to verify your email address."
      footer={<p>Already verified? <Link to="/login">Sign in</Link></p>}
    >
      {message && <p className="notice" role="status">{message}</p>}
      <form className="auth-form" onSubmit={submit}>
        <label className="auth-label" htmlFor="verify-email">
          Email address
          <input id="verify-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)}
            autoComplete="email" required maxLength={254} />
        </label>
        <div className="auth-label">
          Verification code
          <OtpInput value={code} onChange={setCode} disabled={busy} />
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn auth-submit" disabled={busy || code.length !== 6 || !email}>
          {busy && <i className="spinner" aria-hidden="true" />}
          {busy ? "Verifying…" : "Verify email"}
        </button>
      </form>
      <div className="resend-row">
        <span className="field-hint">Didn't get a code?</span>
        <button type="button" className="link" onClick={resend} disabled={seconds > 0 || resending || !email}>
          {resending ? "Sending…" : seconds > 0 ? `Resend in 00:${String(seconds).padStart(2, "0")}` : "Resend code"}
        </button>
      </div>
    </AuthLayout>
  );
}
