import { EmberField } from '../components/flare/EmberField.jsx';
import AuthPanel from '../components/flare/AuthPanel.jsx';

export default function LoginPage() {
  return (
    <div className="auth-screen">
      <EmberField />
      <div className="auth-scanline" aria-hidden="true" />
      <div className="auth-grid" aria-hidden="true" />
      <div className="auth-layout">
        <section className="auth-intro">
          <div className="auth-intro-copy">
            <div className="eyebrow flex items-center gap-3">
              <span className="h-px w-8 bg-accent" /> IDENTITY GATE // 01
            </div>
            <h1 className="font-display">
              See the signal.<br />
              <span className="text-accent">Own the response.</span>
            </h1>
            <p>
              Sign in to the Flare command center and move from alert to action
              without losing the thread.
            </p>
          </div>
          <div className="auth-status" aria-label="System status">
            <span className="status-pip" /> ingestion pipeline nominal <span className="text-muted-foreground">// 2.4.0</span>
          </div>
        </section>
        <section>
          <AuthPanel />
        </section>
      </div>
    </div>
  );
}
