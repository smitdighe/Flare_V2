import { Link } from 'react-router-dom';
import Icon from './Icon.jsx';

export default function AuthShell({ eyebrow, title, description, footer, children }) {
  return (
    <main className="auth-screen">
      <div className="auth-scanline" aria-hidden="true" />
      <div className="auth-grid" aria-hidden="true" />
      <div className="auth-layout">
        <section className="auth-intro">
          <Link to="/" className="auth-brand" aria-label="Return to Flare home">
            <span className="flare-logo-frame"><img src="/flare-logo.png" alt="" className="h-6 w-6 object-contain" /></span>
            <span className="font-mono-ui text-sm font-semibold tracking-[0.1em]">FLARE <span className="text-ash-dark">// ENGINE</span></span>
          </Link>
          <div className="auth-intro-copy">
            <div className="eyebrow flex items-center gap-3"><span className="h-px w-8 bg-amber" /> {eyebrow}</div>
            <h1 className="font-display">{title}</h1>
            <p>{description}</p>
          </div>
          <div className="auth-status font-mono-ui" aria-label="System status"><span className="status-pip" /> ingestion pipeline nominal <span className="text-ash-dark">// 2.4.0</span></div>
        </section>
        <section className="auth-panel-wrap">
          <div className="auth-panel">
            <div className="auth-panel-marker"><Icon name="lock_open" size={15} /> secure access</div>
            {children}
            <div className="auth-footer">{footer}</div>
          </div>
        </section>
      </div>
    </main>
  );
}

export function FormField({ label, id, ...props }) {
  return <label className="auth-field" htmlFor={id}><span>{label}</span><input id={id} {...props} /></label>;
}

export function AuthError({ children }) {
  return <div className="auth-error" role="alert"><Icon name="error" size={16} /><span>{children}</span></div>;
}

export function AuthSubmit({ loading, children }) {
  return <button type="submit" className="terminal-button auth-submit" disabled={loading}>{loading ? 'Working...' : children}<Icon name={loading ? 'sync' : 'arrow_forward'} size={16} /></button>;
}

export function AuthBackLink() {
  return <Link to="/" className="auth-back-link"><Icon name="arrow_back" size={14} /> Back to home</Link>;
}

