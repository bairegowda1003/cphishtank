import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import AuthLayout from "../components/AuthLayout";
import OtpInput from "../components/OtpInput";
import PasswordField from "../components/PasswordField";
import PasswordStrength, { isCommonPassword } from "../components/PasswordStrength";

export default function ResetPassword() {
  const location = useLocation();
  const nav = useNavigate();
  const [email, setEmail] = useState(location.state?.email || "");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
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
    setError("");
    if (code.length !== 6) return setError("Enter all 6 digits.");
    if (password !== confirm) return setError("Passwords do not match.");
    if (password.length < 8 || isCommonPassword(password)) return setError("Choose a password with at least 8 characters that is not common.");
    setBusy(true);
    try {
      await api.resetPassword({ email, otp: code, new_password: password, confirm_password: confirm });
      nav("/login", { replace: true, state: { email, message: "Password reset. Sign in using your new password." } });
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
      const result = await api.resendOtp({ email, purpose: "reset" });
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
      eyebrow="Secure reset"
      title="Choose a new password"
      description="Enter the recovery code sent to your email, then set a new password."
      footer={<p>Need to start over? <Link to="/forgot-password">Request another code</Link></p>}
    >
      {message && <p className="notice" role="status">{message}</p>}
      <form className="auth-form" onSubmit={submit}>
        <label className="auth-label" htmlFor="reset-email">
          Email address
          <input id="reset-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)}
            autoComplete="email" required maxLength={254} />
        </label>
        <div className="auth-label">
          Recovery code
          <OtpInput value={code} onChange={setCode} disabled={busy} />
        </div>
        <PasswordField id="reset-password" label="New password" value={password}
          onChange={(event) => setPassword(event.target.value)} />
        <PasswordStrength password={password} />
        <PasswordField id="reset-confirm" label="Confirm new password" value={confirm}
          onChange={(event) => setConfirm(event.target.value)} />
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn auth-submit" disabled={busy || !email || code.length !== 6}>
          {busy && <i className="spinner" aria-hidden="true" />}
          {busy ? "Updating password…" : "Reset password"}
        </button>
      </form>
      <div className="resend-row">
        <span className="field-hint">Need a new code?</span>
        <button type="button" className="link" onClick={resend} disabled={seconds > 0 || resending || !email}>
          {resending ? "Sending…" : seconds > 0 ? `Resend in 00:${String(seconds).padStart(2, "0")}` : "Resend code"}
        </button>
      </div>
    </AuthLayout>
  );
}
