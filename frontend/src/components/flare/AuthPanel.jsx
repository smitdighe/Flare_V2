import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, Eye, EyeOff, Sparkles, Check } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext.jsx';

export default function AuthPanel({ initialMode = 'signin' }) {
  const [mode, setMode] = useState(initialMode);
  const [showPass, setShowPass] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);

  const { login, register, loginWithGoogle } = useAuth();
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

  const handleGoogleSignIn = async () => {
    setError('');
    setPending(true);
    try {
      await loginWithGoogle({
        id: 'usr_google_quick_access',
        email: 'operator.google@flare.dev',
        name: 'Google Operator',
        role: 'admin',
      });
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Google authentication failed');
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="relative w-full max-w-[420px]">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
        className="relative overflow-hidden rounded-3xl border border-white/10 bg-zinc-950/70 p-6 sm:p-8 backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_24px_64px_-16px_rgba(0,0,0,0.95)]"
      >
        {/* Subtle Specular Top Highlight */}
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent" />

        {/* Brand Mark & Header */}
        <div className="text-center">
          <Link to="/" className="inline-block group">
            <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] p-2 backdrop-blur-xl transition-all duration-300 group-hover:scale-105 group-hover:border-primary/40 shadow-[inset_0_1px_1px_rgba(255,255,255,0.15)]">
              <img src="/flare-logo.png" alt="Flare" className="h-6 w-6 object-contain" />
            </div>
          </Link>
          <h1 className="mt-4 font-sans text-2xl font-bold tracking-tight text-white">
            {mode === 'signin' ? 'Welcome back' : 'Create an account'}
          </h1>
          <p className="mt-1 font-sans text-xs text-zinc-400">
            {mode === 'signin'
              ? 'Sign in to access your incident command center'
              : 'Provision your security workspace in seconds'}
          </p>
        </div>

        {/* Minimal Mode Tab Switcher */}
        <div className="mt-5 flex rounded-xl border border-white/10 bg-white/[0.02] p-1">
          <button
            type="button"
            onClick={() => { setMode('signin'); setError(''); }}
            className={`relative flex-1 rounded-lg py-1.5 font-sans text-xs transition-all ${
              mode === 'signin'
                ? 'font-semibold text-white shadow-sm'
                : 'text-zinc-400 hover:text-white font-medium'
            }`}
          >
            {mode === 'signin' && (
              <motion.span
                layoutId="auth-mode-pill"
                className="absolute inset-0 rounded-lg border border-white/10 bg-white/10"
                transition={{ type: 'spring', stiffness: 450, damping: 35 }}
              />
            )}
            <span className="relative">Sign in</span>
          </button>
          <button
            type="button"
            onClick={() => { setMode('register'); setError(''); }}
            className={`relative flex-1 rounded-lg py-1.5 font-sans text-xs transition-all ${
              mode === 'register'
                ? 'font-semibold text-white shadow-sm'
                : 'text-zinc-400 hover:text-white font-medium'
            }`}
          >
            {mode === 'register' && (
              <motion.span
                layoutId="auth-mode-pill"
                className="absolute inset-0 rounded-lg border border-white/10 bg-white/10"
                transition={{ type: 'spring', stiffness: 450, damping: 35 }}
              />
            )}
            <span className="relative">Create account</span>
          </button>
        </div>

        {/* Quick Demo Access (Minimalist & Convenient) */}
        {mode === 'signin' && (
          <button
            type="button"
            onClick={quickSignin}
            disabled={pending}
            className="mt-4 flex w-full items-center justify-between rounded-xl border border-primary/20 bg-primary/[0.04] px-3.5 py-2 font-sans text-xs text-zinc-300 transition-all hover:border-primary/40 hover:bg-primary/[0.08] hover:text-white disabled:opacity-50"
          >
            <span className="flex items-center gap-2">
              <Sparkles className="h-3.5 w-3.5 text-primary" />
              <span className="font-medium">Quick Demo Access</span>
            </span>
            <span className="rounded-md bg-white/[0.06] px-1.5 py-0.5 font-mono text-[10px] text-primary font-semibold">admin</span>
          </button>
        )}

        {/* Error Alert */}
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -6, height: 0 }}
              animate={{ opacity: 1, y: 0, height: 'auto' }}
              exit={{ opacity: 0, y: -6, height: 0 }}
              className="mt-3 overflow-hidden rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive"
              role="alert"
            >
              {error}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Auth Form */}
        <form onSubmit={submit} className="mt-4 space-y-3.5">
          {mode === 'register' && (
            <div>
              <label className="mb-1.5 block font-sans text-xs font-medium text-zinc-300">
                Full name
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Alex Morgan"
                className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 font-sans text-sm text-white placeholder:text-zinc-600 transition-all focus:border-primary/60 focus:bg-white/[0.06] focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
          )}

          <div>
            <label className="mb-1.5 block font-sans text-xs font-medium text-zinc-300">
              Email address
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@company.com"
              className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 font-sans text-sm text-white placeholder:text-zinc-600 transition-all focus:border-primary/60 focus:bg-white/[0.06] focus:outline-none focus:ring-1 focus:ring-primary/40"
            />
          </div>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="font-sans text-xs font-medium text-zinc-300">
                Password
              </label>
              {mode === 'signin' && (
                <button
                  type="button"
                  onClick={() => setError('Password recovery link dispatched to administrator.')}
                  className="font-sans text-[11px] text-zinc-400 transition-colors hover:text-primary"
                >
                  Forgot password?
                </button>
              )}
            </div>
            <div className="relative">
              <input
                type={showPass ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 pr-10 font-sans text-sm text-white placeholder:text-zinc-600 transition-all focus:border-primary/60 focus:bg-white/[0.06] focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
              <button
                type="button"
                onClick={() => setShowPass((v) => !v)}
                aria-label={showPass ? 'Hide password' : 'Show password'}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 transition-colors hover:text-white"
              >
                {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>

            {/* Password Strength (Register only) */}
            {mode === 'register' && (
              <div className="mt-2 flex items-center gap-1.5">
                {[0, 1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className={`h-1 flex-1 rounded-full transition-all duration-300 ${
                      i < strength
                        ? strength > 2 ? 'bg-emerald-400' : 'bg-primary'
                        : 'bg-white/10'
                    }`}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Primary Submit Action */}
          <button
            type="submit"
            disabled={pending}
            className="group relative mt-2 flex w-full items-center justify-center gap-2 rounded-xl bg-white py-2.5 font-sans text-sm font-semibold text-black transition-all hover:bg-zinc-200 active:scale-[0.99] disabled:opacity-50 shadow-[0_0_20px_rgba(255,255,255,0.15)]"
          >
            <span>
              {pending
                ? 'Authenticating...'
                : mode === 'signin'
                  ? 'Sign in to Flare'
                  : 'Create account'}
            </span>
            <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
          </button>

          {/* Minimal Divider */}
          <div className="relative my-3 flex items-center justify-center">
            <div className="w-full border-t border-white/[0.07]" />
            <span className="relative bg-zinc-950 px-2.5 font-sans text-[11px] text-zinc-500">
              or
            </span>
          </div>

          {/* Clean Google SSO */}
          <button
            type="button"
            onClick={handleGoogleSignIn}
            disabled={pending}
            className="flex w-full items-center justify-center gap-2.5 rounded-xl border border-white/10 bg-white/[0.02] py-2 font-sans text-xs font-medium text-zinc-300 transition-all hover:border-white/20 hover:bg-white/[0.05] hover:text-white disabled:opacity-50"
          >
            <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Continue with Google</span>
          </button>
        </form>

        {/* Footer Navigation */}
        <div className="mt-6 text-center">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 font-sans text-xs text-zinc-500 transition-colors hover:text-zinc-300"
          >
            <span>&larr;</span>
            <span>Back to home</span>
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
