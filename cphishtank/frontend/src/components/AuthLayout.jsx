import { NavLink } from "react-router-dom";

function ShieldArtwork() {
  return (
    <svg className="shield-art" viewBox="0 0 300 300" role="img" aria-label="Shield protecting a link">
      <defs>
        <linearGradient id="shield-fill" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stopColor="var(--accent)" />
          <stop offset="1" stopColor="var(--accent-deep)" />
        </linearGradient>
        <filter id="shield-glow"><feGaussianBlur stdDeviation="10" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
      </defs>
      <circle className="art-orbit orbit-one" cx="150" cy="150" r="118" />
      <circle className="art-orbit orbit-two" cx="150" cy="150" r="94" />
      <path className="art-shield" d="M150 40 226 72v58c0 52-31 94-76 116-45-22-76-64-76-116V72l76-32Z" fill="url(#shield-fill)" filter="url(#shield-glow)" />
      <path className="art-shield-line" d="M150 62 206 86v43c0 39-22 70-56 88-34-18-56-49-56-88V86l56-24Z" />
      <rect className="art-lock" x="125" y="126" width="50" height="42" rx="9" />
      <path className="art-lock" d="M136 126v-11a14 14 0 0 1 28 0v11" />
      <circle className="art-key" cx="150" cy="145" r="4" />
      <path className="art-key" d="M150 149v8" />
      <g className="art-spark"><path d="M56 93v18m-9-9h18" /><path d="M235 178v16m-8-8h16" /></g>
    </svg>
  );
}

export default function AuthLayout({ eyebrow = "CPhishTank security", title, description, children, footer }) {
  return (
    <section className="auth-shell page-enter">
      <div className="auth-form-side">
        <div className="auth-card">
          <NavLink className="auth-mobile-brand brand" to="/">
            <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 2.5 20 6v5.2c0 5.2-3.4 8.6-8 10.3-4.6-1.7-8-5.1-8-10.3V6l8-3.5Z" /></svg></span>
            CPhishTank
          </NavLink>
          <p className="auth-eyebrow">{eyebrow}</p>
          <h1>{title}</h1>
          {description && <p className="auth-description">{description}</p>}
          {children}
          {footer && <div className="auth-footer">{footer}</div>}
        </div>
      </div>
      <aside className="auth-brand-panel" aria-label="About CPhishTank">
        <div className="auth-brand-content">
          <NavLink className="brand auth-panel-brand" to="/">
            <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 2.5 20 6v5.2c0 5.2-3.4 8.6-8 10.3-4.6-1.7-8-5.1-8-10.3V6l8-3.5Z" /></svg></span>
            CPhishTank
          </NavLink>
          <ShieldArtwork />
          <p className="auth-tagline">Know before<br />you click.</p>
          <p className="auth-panel-copy">A clearer view of what's safe, suspicious, and worth a second look.</p>
          <ul className="auth-benefits">
            <li><span>01</span> Spot deceptive links and senders</li>
            <li><span>02</span> See why a message raised a flag</li>
            <li><span>03</span> Keep your scan history in one place</li>
          </ul>
          <p className="auth-panel-foot">Private by design. Built for a safer inbox.</p>
        </div>
      </aside>
    </section>
  );
}
