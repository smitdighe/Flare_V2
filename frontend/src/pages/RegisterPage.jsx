import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, Eye, EyeOff, Lock } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext.jsx';
import { EmberField } from '../components/flare/EmberField.jsx';

export default function RegisterPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const strength = Math.min(
    4,
    (password.length > 7 ? 1 : 0) +
      (/[A-Z]/.test(password) ? 1 : 0) +
      (/\d/.test(password) ? 1 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 1 : 0),
  );

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setPending(true);
    try {
      await register(email, name, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Registration failed');
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="auth-screen">
      <EmberField />
      <div className="auth-scanline" aria-hidden="true" />
      <div className="auth-grid" aria-hidden="true" />
      <div className="auth-layout">
        <section className="auth-intro">
          <div className="auth-intro-copy">
            <div className="eyebrow flex items-center gap-3">
              <span className="h-px w-8 bg-accent" /> IDENTITY GATE // 02
            </div>
            <h1 className="font-display">
              Build a calmer<br />
              <span className="text-accent">security practice.</span>
            </h1>
            <p>
              Create an operator account for the Flare command center.
              Your first workspace is ready when you are.
            </p>
          </div>
          <div className="auth-status" aria-label="System status">
            <span className="status-pip" /> ingestion pipeline nominal <span className="text-muted-foreground">// 2.4.0</span>
          </div>
        </section>
        <section>
          <div className="relative">
            <div className="absolute inset-0 translate-x-2 translate-y-3 border border-accent/25 bg-accent/[0.06]" />
            <motion.div
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
              className="panel scanline relative overflow-hidden"
              style={{ boxShadow: 'var(--shadow-panel)' }}
            >
              <div className="animate-sweep absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-accent/[0.07] to-transparent" />
              <div className="relative p-6 sm:p-8">
                <div className="mono-label flex items-center gap-2">
                  <Lock className="h-3.5 w-3.5" /> secure access
                </div>

                <h2 className="font-display mt-6 text-3xl leading-none tracking-tight">
                  Request clearance
                </h2>
                <p className="mt-2 font-mono text-xs text-muted-foreground">
                  Provision an account against your tenant.
                </p>

                {error && (
                  <div className="mt-4 flex items-start gap-1.5 border border-destructive/45 bg-destructive/8 p-3 font-mono text-[11px] text-destructive" role="alert">
                    <span>{error}</span>
                  </div>
                )}

                <form onSubmit={handleSubmit} className="mt-6 space-y-5">
                  <div>
                    <div className="mono-label mb-2">operator name</div>
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Alex Morgan"
                      className="w-full border border-input bg-secondary/40 px-3 py-3 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-accent focus:bg-secondary/70"
                    />
                  </div>

                  <div>
                    <div className="mono-label mb-2">work email</div>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="operator@company.com"
                      className="w-full border border-input bg-secondary/40 px-3 py-3 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-accent focus:bg-secondary/70"
                    />
                  </div>

                  <div>
                    <div className="mono-label mb-2">password</div>
                    <div className="relative">
                      <input
                        type={showPass ? 'text' : 'password'}
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Minimum 8 characters"
                        minLength={8}
                        className="w-full border border-input bg-secondary/40 px-3 py-3 pr-11 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-accent focus:bg-secondary/70"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPass((v) => !v)}
                        aria-label={showPass ? 'Hide password' : 'Show password'}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-muted-foreground transition-colors hover:text-accent"
                      >
                        {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                    <div className="mt-2 flex gap-1">
                      {[0, 1, 2, 3].map((i) => (
                        <motion.span
                          key={i}
                          animate={{ opacity: i < strength ? 1 : 0.18 }}
                          className={`h-0.5 flex-1 ${strength > 2 ? 'bg-signal-ok' : 'bg-accent'}`}
                        />
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <label className="flex cursor-pointer items-center gap-2 font-mono text-[11px] text-muted-foreground">
                      <input
                        type="checkbox"
                        className="h-3.5 w-3.5 appearance-none border border-input bg-secondary/40 checked:border-accent checked:bg-accent"
                      />
                      Keep me signed in
                    </label>
                  </div>

                  <button
                    type="submit"
                    disabled={pending}
                    className="group relative flex w-full items-center justify-center gap-2 overflow-hidden bg-accent px-4 py-3.5 font-sans text-sm font-medium text-accent-foreground transition-transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-70"
                    style={{ boxShadow: 'var(--shadow-ember)' }}
                  >
                    <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/20 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
                    <span className="relative">
                      {pending ? 'Creating account\u2026' : 'Create operator account'}
                    </span>
                    <ArrowRight className="relative h-4 w-4 transition-transform group-hover:translate-x-1" />
                  </button>
                </form>

                <div className="mt-6 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                  <span>Already registered?</span>
                  <Link to="/login" className="text-accent hover:underline">
                    Sign in <span aria-hidden="true">&uarr;</span>
                  </Link>
                  <Link to="/" className="mono-label flex items-center gap-1 text-muted-foreground hover:text-foreground">
                    <span className="text-xs">&larr;</span> Back to home
                  </Link>
                </div>
              </div>
            </motion.div>
          </div>
        </section>
      </div>
    </div>
  );
}
