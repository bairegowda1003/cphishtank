import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import AuthLayout from "../components/AuthLayout";
import PasswordField from "../components/PasswordField";
import { useAuth } from "../auth";

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState(location.state?.email || "");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login({ email, password, remember_me: remember });
      nav("/", { replace: true });
    } catch (issue) {
      if (issue.status === 403) {
        nav("/verify-email", { replace: true, state: { email, message: issue.message } });
      } else {
        setError(issue.status === 401 ? "Email or password is incorrect." : issue.message);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Welcome back"
      title="Sign in to your account"
      description="Your scans and security insights, right where you left them."
      footer={<p>New to CPhishTank? <Link to="/register">Create an account</Link></p>}
    >
      {location.state?.message && <p className="notice" role="status">{location.state.message}</p>}
      <form className="auth-form" onSubmit={submit}>
        <label className="auth-label" htmlFor="login-email">
          Email address
          <input id="login-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)}
            autoComplete="email" required maxLength={254} />
        </label>
        <PasswordField id="login-password" label="Password" value={password}
          onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" minLength={1} />
        <div className="auth-inline-row">
          <label className="remember-check"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} /> Keep me signed in</label>
          <Link to="/forgot-password">Forgot password?</Link>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn auth-submit" disabled={busy}>
          {busy && <i className="spinner" aria-hidden="true" />}
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </AuthLayout>
  );
}
