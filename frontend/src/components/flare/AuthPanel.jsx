import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, Eye, EyeOff, Fingerprint, Lock, ShieldCheck, Info } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext.jsx';

const ROLES = [
  { id: 'analyst', label: 'analyst', hint: 'Triage alerts, run playbooks, export reports.' },
  { id: 'admin', label: 'admin', hint: 'Full control: users, rules, tenants, scheduler.' },
  { id: 'viewer', label: 'viewer', hint: 'Read-only. Cannot mutate rules or playbooks.' },
];

function Field({ label, children }) {
  return (
    <div>
      <div className="mono-label mb-2">{label}</div>
      {children}
    </div>
  );
}

export default function AuthPanel() {
  const [mode, setMode] = useState('signin');
  const [showPass, setShowPass] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('analyst');
  const [openRoleHint, setOpenRoleHint] = useState(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);

  const { login, register } = useAuth();
  const navigate = useNavigate();

  const strength = Math.min(
    4,
    (password.length > 7 ? 1 : 0) +
      (/[A-Z]/.test(password) ? 1 : 0) +
      (/\d/.test(password) ? 1 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 1 : 0),
  );

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setPending(true);
    try {
      if (mode === 'signin') {
        await login(email, password);
        navigate('/dashboard');
      } else {
        if (password.length < 8) {
          setError('Password must be at least 8 characters');
          setPending(false);
          return;
        }
        await register(email, name, password);
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setPending(false);
    }
  };

  const quickSignin = async () => {
    setError('');
    setPending(true);
    try {
      await login('admin@flare.dev', 'admin123');
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setPending(false);
    }
  };

  return (
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

          <div className="mt-5 flex gap-1 border border-border p-1">
            {['signin', 'register'].map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => { setMode(m); setError(''); }}
                className="relative flex-1 px-3 py-2"
              >
                {mode === m && (
                  <motion.span
                    layoutId="mode-pill"
                    className="absolute inset-0 bg-accent"
                    transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                  />
                )}
                <span
                  className={`mono-label relative ${mode === m ? 'text-accent-foreground' : ''}`}
                >
                  {m === 'signin' ? 'sign in' : 'new operator'}
                </span>
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            <motion.div
              key={mode}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.25 }}
            >
              <h2 className="font-display mt-6 text-3xl leading-none tracking-tight">
                {mode === 'signin' ? 'Operator sign in' : 'Request clearance'}
              </h2>
              <p className="mt-2 font-mono text-xs text-muted-foreground">
                {mode === 'signin'
                  ? 'Use your Flare credentials to continue.'
                  : 'Provision an account against your tenant.'}
              </p>

              {error && (
                <div className="mt-4 flex items-start gap-1.5 border border-destructive/45 bg-destructive/8 p-3 font-mono text-[11px] text-destructive" role="alert">
                  <span>{error}</span>
                </div>
              )}

              {mode === 'signin' && (
                <button
                  type="button"
                  onClick={quickSignin}
                  disabled={pending}
                  className="mt-4 w-full border border-amber/50 bg-amber/10 px-4 py-2.5 font-mono text-[11px] uppercase tracking-[0.1em] text-amber transition-colors hover:bg-amber/20 disabled:opacity-50"
                >
                  Quick demo sign in <span className="opacity-60">// admin</span>
                </button>
              )}

              <form onSubmit={submit} className="mt-4 space-y-5">
                {mode === 'register' && (
                  <Field label="operator name">
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Alex Morgan"
                      className="w-full border border-input bg-secondary/40 px-3 py-3 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-accent focus:bg-secondary/70"
                    />
                  </Field>
                )}

                <Field label="work email">
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="operator@company.com"
                    className="w-full border border-input bg-secondary/40 px-3 py-3 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-accent focus:bg-secondary/70"
                  />
                </Field>

                <Field label="password">
                  <div className="relative">
                    <input
                      type={showPass ? 'text' : 'password'}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
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
                  {mode === 'register' && (
                    <div className="mt-2 flex gap-1">
                      {[0, 1, 2, 3].map((i) => (
                        <motion.span
                          key={i}
                          animate={{ opacity: i < strength ? 1 : 0.18 }}
                          className={`h-0.5 flex-1 ${strength > 2 ? 'bg-signal-ok' : 'bg-accent'}`}
                        />
                      ))}
                    </div>
                  )}
                </Field>

                {mode === 'register' && (
                  <div>
                    <div className="mono-label mb-2">requested role</div>
                    <div className="grid grid-cols-3 gap-1">
                      {ROLES.map((r) => (
                        <div key={r.id} className="relative">
                          <button
                            type="button"
                            onClick={() => {
                              setRole(r.id);
                              setOpenRoleHint(openRoleHint === r.id ? null : r.id);
                            }}
                            className={`mono-label w-full border px-2 py-2.5 transition-colors ${
                              role === r.id
                                ? 'border-accent bg-accent/10 text-accent'
                                : 'border-border hover:border-accent/50'
                            }`}
                          >
                            {r.label}
                          </button>
                          <AnimatePresence>
                            {openRoleHint === r.id && (
                              <motion.div
                                initial={{ opacity: 0, y: 6, scale: 0.96 }}
                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                exit={{ opacity: 0, y: 6, scale: 0.96 }}
                                className="absolute bottom-full left-0 z-20 mb-2 w-52 border border-border bg-popover p-3 font-mono text-[11px] leading-relaxed text-muted-foreground"
                              >
                                <Info className="mb-1 h-3 w-3 text-accent" />
                                {r.hint}
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <label className="flex cursor-pointer items-center gap-2 font-mono text-[11px] text-muted-foreground">
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 appearance-none border border-input bg-secondary/40 checked:border-accent checked:bg-accent"
                    />
                    Keep me signed in
                  </label>
                  <button
                    type="button"
                    onClick={() => setError('Password recovery is not enabled in this environment.')}
                    className="font-mono text-[11px] text-accent underline-offset-4 hover:underline"
                  >
                    Forgot password?
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={pending}
                  className="group relative flex w-full items-center justify-center gap-2 overflow-hidden bg-accent px-4 py-3.5 font-sans text-sm font-medium text-accent-foreground transition-transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-70"
                  style={{ boxShadow: 'var(--shadow-ember)' }}
                >
                  <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/20 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
                  <span className="relative">
                    {pending
                      ? 'Authenticating\u2026'
                      : mode === 'signin'
                        ? 'Enter command center'
                        : 'Request access'}
                  </span>
                  <ArrowRight className="relative h-4 w-4 transition-transform group-hover:translate-x-1" />
                </button>
              </form>
            </motion.div>
          </AnimatePresence>

          <div className="mt-6 flex items-center justify-between border-t border-border pt-4">
            <span className="mono-label flex items-center gap-2">
              <ShieldCheck className="h-3.5 w-3.5 text-signal-ok" /> jwt \u00b7 30m access
            </span>
            <button
              type="button"
              onClick={() => setError('Hardware key not enrolled. Ask an admin to register a passkey.')}
              className="mono-label flex items-center gap-2 text-accent transition-opacity hover:opacity-70"
            >
              <Fingerprint className="h-3.5 w-3.5" /> passkey
            </button>
          </div>

          <div className="mt-6 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
            {mode === 'signin' ? (
              <>
                <span>New operator?</span>
                <button type="button" onClick={() => { setMode('register'); setError(''); }} className="text-accent hover:underline">
                  Create an account <span aria-hidden="true">&uarr;</span>
                </button>
              </>
            ) : (
              <>
                <span>Already registered?</span>
                <button type="button" onClick={() => { setMode('signin'); setError(''); }} className="text-accent hover:underline">
                  Sign in <span aria-hidden="true">&uarr;</span>
                </button>
              </>
            )}
            <Link to="/" className="mono-label flex items-center gap-1 text-muted-foreground hover:text-foreground">
              <span className="text-xs">&larr;</span> Back to home
            </Link>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
