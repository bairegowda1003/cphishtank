import { useState } from "react";

export default function PasswordField({
  id, label = "Password", value, onChange, autoComplete = "new-password",
  required = true, minLength = 8, maxLength = 128, helper,
}) {
  const [visible, setVisible] = useState(false);
  return (
    <label className="auth-label" htmlFor={id}>
      {label}
      <span className="password-wrap">
        <input
          id={id}
          type={visible ? "text" : "password"}
          value={value}
          onChange={onChange}
          autoComplete={autoComplete}
          required={required}
          minLength={minLength}
          maxLength={maxLength}
        />
        <button
          className="password-toggle"
          type="button"
          aria-label={visible ? "Hide password" : "Show password"}
          aria-pressed={visible}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? (
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8" /><path d="M9.9 5.2A10.7 10.7 0 0 1 12 5c5.4 0 9 5 9 7a8.8 8.8 0 0 1-3.1 3.9M6.2 6.3C3.9 7.8 3 10.2 3 12c0 2 3.6 7 9 7 1.1 0 2.1-.2 3-.6" /></svg>
          ) : (
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12s3.2-7 9-7 9 7 9 7-3.2 7-9 7-9-7-9-7Z" /><circle cx="12" cy="12" r="2.5" /></svg>
          )}
        </button>
      </span>
      {helper && <span className="field-hint">{helper}</span>}
    </label>
  );
}
