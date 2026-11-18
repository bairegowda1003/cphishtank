const COMMON = new Set([
  "password", "password1", "password123", "12345678", "123456789",
  "qwerty123", "qwertyuiop", "letmein123", "welcome123", "admin1234",
  "iloveyou", "abc12345", "11111111", "changeme123",
]);

export function isCommonPassword(password) {
  return COMMON.has(password.trim().toLowerCase());
}

export default function PasswordStrength({ password }) {
  if (!password) return null;
  const common = isCommonPassword(password);
  const score = common ? 1 : Math.min(
    4,
    (password.length >= 8 ? 1 : 0)
      + (password.length >= 12 ? 1 : 0)
      + (/[A-Z]/.test(password) && /[a-z]/.test(password) ? 1 : 0)
      + (/\d/.test(password) || /[^A-Za-z0-9]/.test(password) ? 1 : 0),
  );
  const labels = ["", "Weak", "Fair", "Good", "Strong"];
  return (
    <div className={`password-strength strength-${score}`} aria-live="polite">
      <div className="strength-track" aria-hidden="true"><i style={{ width: `${score * 25}%` }} /></div>
      <span>{common ? "Common password — choose another" : `${labels[score] || "Too short"} password`}</span>
    </div>
  );
}
