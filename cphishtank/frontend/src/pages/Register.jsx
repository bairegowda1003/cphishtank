import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import AuthLayout from "../components/AuthLayout";
import PasswordField from "../components/PasswordField";
import PasswordStrength, { isCommonPassword } from "../components/PasswordStrength";

export default function Register() {
  const nav = useNavigate();
  const [fields, setFields] = useState({ name: "", email: "", password: "", confirm: "" });
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (key) => (event) => setFields((current) => ({ ...current, [key]: event.target.value }));
  const passwordOkay = fields.password.length >= 8 && !isCommonPassword(fields.password);

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (fields.password !== fields.confirm) return setError("Passwords do not match.");
    if (!passwordOkay) return setError("Choose a password with at least 8 characters that is not common.");
    if (!accepted) return setError("Accept the terms to create an account.");
    setBusy(true);
    try {
      await api.register({
        name: fields.name, email: fields.email, password: fields.password,
        confirm_password: fields.confirm, accepted_terms: accepted,
      });
      nav("/verify-email", { state: { email: fields.email, message: "Your account is ready. Enter the code we sent to your email." } });
    } catch (issue) {
      setError(issue.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Get started"
      title="Create your account"
      description="A little more confidence for every message you check."
      footer={<p>Already have an account? <Link to="/login">Sign in</Link></p>}
    >
      <form className="auth-form" onSubmit={submit}>
        <label className="auth-label" htmlFor="register-name">
          Name
          <input id="register-name" value={fields.name} onChange={set("name")} autoComplete="name" required maxLength={120} />
        </label>
        <label className="auth-label" htmlFor="register-email">
          Email address
          <input id="register-email" type="email" value={fields.email} onChange={set("email")}
            autoComplete="email" required maxLength={254} />
        </label>
        <div className="auth-field-group">
          <PasswordField id="register-password" label="Password" value={fields.password} onChange={set("password")} />
          <PasswordStrength password={fields.password} />
          <p className="field-hint">Use at least 8 characters. Common passwords aren't accepted.</p>
        </div>
        <PasswordField id="register-confirm" label="Confirm password" value={fields.confirm}
          onChange={set("confirm")} autoComplete="new-password" />
        <label className="remember-check terms-check">
          <input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} required />
          <span>I agree to the terms and privacy notice.</span>
        </label>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn auth-submit" disabled={busy || !passwordOkay || !accepted}>
          {busy && <i className="spinner" aria-hidden="true" />}
          {busy ? "Creating account…" : "Create account"}
        </button>
      </form>
    </AuthLayout>
  );
}
