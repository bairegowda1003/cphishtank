import { Navigate, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { useAuth } from "./auth";
import { useTheme } from "./theme";
import Scan from "./pages/Scan";
import History from "./pages/History";
import Dashboard from "./pages/Dashboard";
import Survey from "./pages/Survey";
import Admin from "./pages/Admin";
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import ChangePassword from "./pages/ChangePassword";

function Protected({ children, admin }) {
  const { user, ready } = useAuth();
  if (!ready) return <p className="muted pad" role="status">Loading your account…</p>;
  if (!user) return <Navigate to="/login" replace />;
  if (admin && !user.is_admin) return <Navigate to="/" replace />;
  return children;
}

function ThemeButton() {
  const { theme, toggleTheme } = useTheme();
  const label = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  return (
    <button className="icon-btn theme-toggle" type="button" onClick={toggleTheme} aria-label={label} title={label}>
      {theme === "dark" ? (
        <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></svg>
      ) : (
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.2 15.2A8.4 8.4 0 0 1 8.8 3.8 8.5 8.5 0 1 0 20.2 15.2Z" /></svg>
      )}
    </button>
  );
}

function Brand() {
  return (
    <NavLink to="/" className="brand" aria-label="CPhishTank home">
      <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 2.5 20 6v5.2c0 5.2-3.4 8.6-8 10.3-4.6-1.7-8-5.1-8-10.3V6l8-3.5Z" /><path d="m8.6 11.8 2.2 2.2 4.7-5" /></svg></span>
      <span>CPhishTank</span>
    </NavLink>
  );
}

export default function App() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  return (
    <div className="app-shell">
      <header className="top">
        <Brand />
        <nav aria-label="Main navigation">
          <NavLink to="/" end>Scan</NavLink>
          {user && <NavLink to="/history">History</NavLink>}
          {user && <NavLink to="/dashboard">Dashboard</NavLink>}
          <NavLink to="/survey">Awareness</NavLink>
          {user?.is_admin && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <div className="top-actions">
          <ThemeButton />
          {user ? (
            <details className="profile-menu">
              <summary aria-label="Open account menu">
                <span className="avatar" aria-hidden="true">{user.name?.trim()?.[0]?.toUpperCase() || "U"}</span>
                <span className="profile-name">{user.name}</span>
                <svg className="chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
              </summary>
              <div className="profile-dropdown">
                <span className="profile-email">{user.email}</span>
                <NavLink to="/change-password">Change password</NavLink>
                <button type="button" onClick={() => { logout(); nav("/"); }}>Sign out</button>
              </div>
            </details>
          ) : (
            <div className="guest-actions">
              <NavLink to="/login" className="top-login">Sign in</NavLink>
              <NavLink to="/register" className="btn small">Create account</NavLink>
            </div>
          )}
        </div>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Scan />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/change-password" element={<Protected><ChangePassword /></Protected>} />
          <Route path="/survey" element={<Survey />} />
          <Route path="/history" element={<Protected><History /></Protected>} />
          <Route path="/history/:id" element={<Protected><History /></Protected>} />
          <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
          <Route path="/admin" element={<Protected admin><Admin /></Protected>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="foot muted">CPhishTank is a decision aid, not a guarantee. When in doubt, contact the sender through an official channel.</footer>
    </div>
  );
}
