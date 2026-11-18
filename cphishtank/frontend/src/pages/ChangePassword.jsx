import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import AuthLayout from "../components/AuthLayout";
import PasswordField from "../components/PasswordField";
import PasswordStrength, { isCommonPassword } from "../components/PasswordStrength";

export default function ChangePassword() {
  const nav = useNavigate();
  const { logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (password !== confirm) return setError("Passwords do not match.");
    if (password.length < 8 || isCommonPassword(password)) return setError("Choose a password with at least 8 characters that is not common.");
    setBusy(true);
    try {
      await api.changePassword({ current_password: current, new_password: password, confirm_password: confirm });
      logout();
      nav("/login", { replace: true, state: { message: "Password changed. Sign in again." } });
    } catch (issue) {
      setError(issue.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout eyebrow="Account security" title="Change your password" description="Changing your password signs out all active sessions.">
      <form className="auth-form" onSubmit={submit}>
        <PasswordField id="current-password" label="Current password" value={current}
          onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" minLength={1} />
        <PasswordField id="change-password" label="New password" value={password} onChange={(event) => setPassword(event.target.value)} />
        <PasswordStrength password={password} />
        <PasswordField id="change-confirm" label="Confirm new password" value={confirm}
          onChange={(event) => setConfirm(event.target.value)} />
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn auth-submit" disabled={busy}>
          {busy && <i className="spinner" aria-hidden="true" />}
          {busy ? "Updating…" : "Update password"}
        </button>
      </form>
    </AuthLayout>
  );
}
