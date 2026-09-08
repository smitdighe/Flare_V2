import { useState, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  User,
  Shield,
  Palette,
  Sliders,
  Radio,
  Cpu,
  Lock,
  Key,
  Volume2,
  VolumeX,
  Monitor,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Zap,
  Fingerprint,
} from "lucide-react";
import { useAuth } from "../../contexts/AuthContext.jsx";
import { useTheme } from "../../contexts/ThemeContext.jsx";

const API_BASE = import.meta.env.VITE_API_BASE || "";

const TABS = [
  { id: "profile", label: "Operator Profile", icon: User },
  { id: "security", label: "Security & Access", icon: Shield },
  { id: "appearance", label: "Appearance & HUD", icon: Palette },
  { id: "telemetry", label: "Telemetry & Stream", icon: Radio },
  { id: "diagnostics", label: "System Diagnostics", icon: Cpu },
];

function playTacticalChime() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc1 = ctx.createOscillator();
    const osc2 = ctx.createOscillator();
    const gain = ctx.createGain();

    osc1.type = "sine";
    osc1.frequency.setValueAtTime(880, ctx.currentTime);
    osc1.frequency.exponentialRampToValueAtTime(1320, ctx.currentTime + 0.08);

    osc2.type = "triangle";
    osc2.frequency.setValueAtTime(440, ctx.currentTime + 0.09);
    osc2.frequency.exponentialRampToValueAtTime(1760, ctx.currentTime + 0.2);

    gain.gain.setValueAtTime(0.05, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(ctx.destination);

    osc1.start(ctx.currentTime);
    osc1.stop(ctx.currentTime + 0.09);
    osc2.start(ctx.currentTime + 0.09);
    osc2.stop(ctx.currentTime + 0.25);
  } catch {
    // AudioContext not allowed before user gesture
  }
}

export default function SettingsPanel({ density, onDensityChange, onNavigate }) {
  const { user, token, authFetch, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState("profile");

  // Profile Form State
  const [name, setName] = useState(user?.name || "");
  const [email, setEmail] = useState(user?.email || "");
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileFeedback, setProfileFeedback] = useState(null);

  // Security Form State
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [securitySaving, setSecuritySaving] = useState(false);
  const [securityFeedback, setSecurityFeedback] = useState(null);

  // Appearance & Audio State
  const [scanlines, setScanlines] = useState(() => {
    return localStorage.getItem("flare_scanlines") !== "disabled";
  });
  const [audioAlerts, setAudioAlerts] = useState(() => {
    return localStorage.getItem("flare_audio_alerts") === "enabled";
  });

  // Telemetry Settings
  const [streamTransport, setStreamTransport] = useState(() => {
    return localStorage.getItem("flare_stream_transport") || "websocket";
  });
  const [alertThreshold, setAlertThreshold] = useState(() => {
    return localStorage.getItem("flare_alert_threshold") || "all";
  });

  // Keep local profile form synced with user context
  useEffect(() => {
    if (user?.name) setName(user.name);
    if (user?.email) setEmail(user.email);
  }, [user]);

  const handleSaveProfile = async (e) => {
    e?.preventDefault();
    setProfileSaving(true);
    setProfileFeedback(null);

    try {
      if (token?.startsWith("mock_") || localStorage.getItem("flare_mock_user")) {
        // Quick access / mock user
        const updatedUser = { ...(user || {}), name, email };
        localStorage.setItem("flare_mock_user", JSON.stringify(updatedUser));
        setProfileFeedback({ type: "success", message: "Operator profile updated in session." });
        setProfileSaving(false);
        return;
      }

      const res = await authFetch(`${API_BASE}/api/v1/auth/profile`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email }),
      });

      if (res.ok) {
        setProfileFeedback({ type: "success", message: "Operator profile updated successfully." });
      } else {
        const errorData = await res.json().catch(() => ({}));
        setProfileFeedback({
          type: "error",
          message: errorData.detail || `Update failed: HTTP ${res.status}`,
        });
      }
    } catch (err) {
      setProfileFeedback({ type: "error", message: err.message || "Network communication error." });
    } finally {
      setProfileSaving(false);
    }
  };

  const handleChangePassword = async (e) => {
    e?.preventDefault();
    if (!currentPassword || !newPassword) {
      setSecurityFeedback({ type: "error", message: "Please provide both current and new passwords." });
      return;
    }
    if (newPassword !== confirmPassword) {
      setSecurityFeedback({ type: "error", message: "New passwords do not match." });
      return;
    }
    if (newPassword.length < 8) {
      setSecurityFeedback({ type: "error", message: "Password must be at least 8 characters long." });
      return;
    }

    setSecuritySaving(true);
    setSecurityFeedback(null);

    try {
      if (token?.startsWith("mock_")) {
        setSecurityFeedback({ type: "success", message: "Password updated in session credentials." });
        setCurrentPassword("");
        setNewPassword("");
        setConfirmPassword("");
        setSecuritySaving(false);
        return;
      }

      const res = await authFetch(`${API_BASE}/api/v1/auth/change-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });

      if (res.ok) {
        setSecurityFeedback({ type: "success", message: "Cryptographic credentials updated." });
        setCurrentPassword("");
        setNewPassword("");
        setConfirmPassword("");
      } else {
        const errJson = await res.json().catch(() => ({}));
        setSecurityFeedback({
          type: "error",
          message: errJson.detail || "Failed to update password. Verify current password.",
        });
      }
    } catch (err) {
      setSecurityFeedback({ type: "error", message: err.message || "Communication failure." });
    } finally {
      setSecuritySaving(false);
    }
  };

  const toggleScanlines = () => {
    const next = !scanlines;
    setScanlines(next);
    localStorage.setItem("flare_scanlines", next ? "enabled" : "disabled");
  };

  const toggleAudioAlerts = () => {
    const next = !audioAlerts;
    setAudioAlerts(next);
    localStorage.setItem("flare_audio_alerts", next ? "enabled" : "disabled");
    if (next) playTacticalChime();
  };

  const handleTransportChange = (val) => {
    setStreamTransport(val);
    localStorage.setItem("flare_stream_transport", val);
  };

  const handleThresholdChange = (val) => {
    setAlertThreshold(val);
    localStorage.setItem("flare_alert_threshold", val);
  };

  return (
    <section className="dashboard-panel min-w-0 overflow-hidden border border-border bg-card">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border px-5 py-4 bg-secondary/20">
        <div>
          <div className="mono-label flex items-center gap-2 text-primary">
            <span className="h-1.5 w-1.5 rounded-full bg-signal animate-blink" />
            CONSOLE SYSTEM // CONFIGURATION
          </div>
          <h2 className="mt-1 font-display text-xl tracking-tight text-foreground">
            Settings & Operator Preferences
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden items-center gap-1.5 border border-border bg-background/50 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground sm:inline-flex">
            <Fingerprint className="h-3 w-3 text-primary" />
            CLEARANCE: <strong className="text-foreground">{user?.role?.toUpperCase() || "ADMIN"}</strong>
          </span>
          <span className="inline-flex items-center gap-1.5 border border-signal/40 bg-signal/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-signal">
            <span className="h-1.5 w-1.5 rounded-full bg-signal animate-blink" />
            SYSTEM NOMINAL
          </span>
        </div>
      </div>

      {/* Tabs Navigation Strip */}
      <div className="flex flex-wrap border-b border-border bg-background/40">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`group relative flex items-center gap-2 px-4 py-3 font-mono text-[11px] uppercase tracking-[0.14em] transition-colors ${
                isActive
                  ? "border-b-2 border-primary bg-primary/10 text-primary font-semibold"
                  : "text-muted-foreground hover:bg-secondary/40 hover:text-foreground"
              }`}
            >
              <Icon className={`h-3.5 w-3.5 transition-colors ${isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div className="p-5 md:p-7">
        <AnimatePresence mode="wait">
          {/* TAB 1: PROFILE */}
          {activeTab === "profile" && (
            <motion.div
              key="tab-profile"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 }}
              className="space-y-6"
            >
              {/* Operator Badge Card */}
              <div className="grid gap-4 border border-border bg-secondary/15 p-4 sm:grid-cols-[auto_1fr_auto] sm:items-center">
                <div className="flex h-12 w-12 items-center justify-center border border-primary/50 bg-primary/10 text-primary">
                  <User className="h-6 w-6" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-foreground">
                      {user?.name || "Threat Operator"}
                    </span>
                    <span className="border border-signal/60 bg-signal/15 px-1.5 py-0.2 font-mono text-[9px] uppercase tracking-wider text-signal">
                      Active
                    </span>
                  </div>
                  <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
                    {user?.email || "operator@flare.dev"}
                  </div>
                  <div className="mono-label mt-1 text-[9px] text-muted-foreground">
                    OPERATOR ID: <span className="text-foreground">{user?.id || "usr_soc_operator"}</span> // CLEARANCE: <span className="text-primary">{user?.role?.toUpperCase() || "ADMIN"}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 border border-border px-2 py-1 font-mono text-[10px] text-muted-foreground">
                    <CheckCircle2 className="h-3 w-3 text-signal" /> Session Verified
                  </span>
                </div>
              </div>

              {/* Edit Profile Form */}
              <form onSubmit={handleSaveProfile} className="space-y-4">
                <div className="border-b border-border pb-2">
                  <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-primary">
                    Update Operator Record
                  </h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Changes will reflect across incident audit trails and triage signoffs.
                  </p>
                </div>

                {profileFeedback && (
                  <div
                    className={`flex items-center gap-2 border px-3 py-2 font-mono text-xs ${
                      profileFeedback.type === "success"
                        ? "border-signal/50 bg-signal/10 text-signal"
                        : "border-destructive/50 bg-destructive/10 text-destructive"
                    }`}
                  >
                    {profileFeedback.type === "success" ? (
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                    )}
                    <span>{profileFeedback.message}</span>
                  </div>
                )}

                <div className="grid gap-4 md:grid-cols-2">
                  <div>
                    <label className="mono-label mb-1.5 block text-[10px] text-muted-foreground">
                      OPERATOR FULL NAME
                    </label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Atharva Dighe"
                      required
                      className="w-full border border-border bg-secondary/30 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:bg-background focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="mono-label mb-1.5 block text-[10px] text-muted-foreground">
                      EMAIL ADDRESS
                    </label>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="e.g. operator@flare.dev"
                      required
                      className="w-full border border-border bg-secondary/30 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:bg-background focus:outline-none"
                    />
                  </div>
                </div>

                <div className="flex items-center gap-3 pt-2">
                  <button
                    type="submit"
                    disabled={profileSaving}
                    className="flex items-center gap-2 border border-primary bg-primary/10 px-4 py-2 font-mono text-xs uppercase tracking-[0.16em] text-primary transition-colors hover:bg-primary hover:text-primary-foreground disabled:opacity-50"
                  >
                    {profileSaving ? (
                      <>
                        <RefreshCw className="h-3 w-3 animate-spin" />
                        Saving Changes...
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Commit Profile Updates
                      </>
                    )}
                  </button>
                  <span className="mono-label text-[9px] text-muted-foreground">
                    // Audited via PUT /api/v1/auth/profile
                  </span>
                </div>
              </form>
            </motion.div>
          )}

          {/* TAB 2: SECURITY */}
          {activeTab === "security" && (
            <motion.div
              key="tab-security"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 }}
              className="space-y-6"
            >
              {/* Change Password Card */}
              <form onSubmit={handleChangePassword} className="space-y-4">
                <div className="border-b border-border pb-2">
                  <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-primary flex items-center gap-2">
                    <Lock className="h-3.5 w-3.5" /> Cryptographic Authentication
                  </h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Rotate your SOC credentials. Sessions across other devices will be challenged.
                  </p>
                </div>

                {securityFeedback && (
                  <div
                    className={`flex items-center gap-2 border px-3 py-2 font-mono text-xs ${
                      securityFeedback.type === "success"
                        ? "border-signal/50 bg-signal/10 text-signal"
                        : "border-destructive/50 bg-destructive/10 text-destructive"
                    }`}
                  >
                    {securityFeedback.type === "success" ? (
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                    )}
                    <span>{securityFeedback.message}</span>
                  </div>
                )}

                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <label className="mono-label mb-1.5 block text-[10px] text-muted-foreground">
                      CURRENT PASSWORD
                    </label>
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full border border-border bg-secondary/30 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:bg-background focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="mono-label mb-1.5 block text-[10px] text-muted-foreground">
                      NEW PASSWORD
                    </label>
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Min. 8 chars"
                      className="w-full border border-border bg-secondary/30 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:bg-background focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="mono-label mb-1.5 block text-[10px] text-muted-foreground">
                      CONFIRM NEW PASSWORD
                    </label>
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Repeat new password"
                      className="w-full border border-border bg-secondary/30 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:bg-background focus:outline-none"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={securitySaving || !currentPassword || !newPassword}
                  className="flex items-center gap-2 border border-primary bg-primary/10 px-4 py-2 font-mono text-xs uppercase tracking-[0.16em] text-primary transition-colors hover:bg-primary hover:text-primary-foreground disabled:opacity-50"
                >
                  <Key className="h-3.5 w-3.5" />
                  {securitySaving ? "Rotating Credentials..." : "Update Security Credentials"}
                </button>
              </form>

              {/* Security Audit Details Grid */}
              <div className="grid gap-3 pt-2 sm:grid-cols-2 lg:grid-cols-3">
                <div className="border border-border bg-secondary/10 p-3.5">
                  <div className="mono-label text-[9px] text-muted-foreground">TOKEN PROTOCOL</div>
                  <div className="mt-1 font-mono text-sm text-foreground">HMAC-SHA256 (JWT)</div>
                  <div className="mono-label mt-1 text-[9px] text-signal">30m access / 7d sliding</div>
                </div>

                <div className="border border-border bg-secondary/10 p-3.5">
                  <div className="mono-label text-[9px] text-muted-foreground">HARDWARE ATTESTATION</div>
                  <div className="mt-1 font-mono text-sm text-foreground">WebAuthn / FIDO2</div>
                  <div className="mono-label mt-1 text-[9px] text-signal">Ready for Enrolment</div>
                </div>

                <div className="border border-border bg-secondary/10 p-3.5 sm:col-span-2 lg:col-span-1">
                  <div className="mono-label text-[9px] text-muted-foreground">AUDIT INTEGRITY</div>
                  <div className="mt-1 font-mono text-sm text-foreground">Append-only Ledger</div>
                  <div className="mono-label mt-1 text-[9px] text-primary">Zero-deletion policy</div>
                </div>
              </div>

              {/* Emergency Session Revocation */}
              <div className="border border-destructive/40 bg-destructive/5 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-xs uppercase tracking-wider text-destructive font-semibold">
                      Emergency Console Signout
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Immediately purges active session tokens and local state from this browser.
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={logout}
                    className="border border-destructive/60 bg-destructive/10 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-destructive hover:bg-destructive hover:text-destructive-foreground transition-colors"
                  >
                    Terminate Session
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {/* TAB 3: APPEARANCE */}
          {activeTab === "appearance" && (
            <motion.div
              key="tab-appearance"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 }}
              className="space-y-6"
            >
              <div>
                <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-primary">
                  HUD & Console Visual Modes
                </h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Tailor information density and visual contrast for low-light SOC or high-illumination field environments.
                </p>
              </div>

              {/* Theme Selector */}
              <div className="space-y-2">
                <div className="mono-label text-[10px] text-muted-foreground">COLOR THEME</div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <button
                    type="button"
                    onClick={() => setTheme("dark")}
                    className={`flex items-center gap-3 border p-3.5 text-left transition-colors ${
                      theme === "dark"
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(235,115,26,0.15)]"
                        : "border-border bg-secondary/15 hover:border-border/80"
                    }`}
                  >
                    <div className="flex h-9 w-9 items-center justify-center border border-primary/50 bg-background text-primary">
                      <Monitor className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        Obsidian Amber (Dark SOC)
                      </div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        Warm near-black console with phosphor amber highlights
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setTheme("light")}
                    className={`flex items-center gap-3 border p-3.5 text-left transition-colors ${
                      theme === "light"
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(235,115,26,0.15)]"
                        : "border-border bg-secondary/15 hover:border-border/80"
                    }`}
                  >
                    <div className="flex h-9 w-9 items-center justify-center border border-border bg-foreground text-background">
                      <Monitor className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        Tactical High-Contrast (Light)
                      </div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        High visibility daylight palette for bright operations
                      </div>
                    </div>
                  </button>
                </div>
              </div>

              {/* Information Density */}
              <div className="space-y-2">
                <div className="mono-label text-[10px] text-muted-foreground">INFORMATION DENSITY</div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <button
                    type="button"
                    onClick={() => onDensityChange?.("comfortable")}
                    className={`flex items-center gap-3 border p-3.5 text-left transition-colors ${
                      density === "comfortable"
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(235,115,26,0.15)]"
                        : "border-border bg-secondary/15 hover:border-border/80"
                    }`}
                  >
                    <Sliders className="h-5 w-5 text-primary" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">Comfortable Layout</div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        Standard row height with generous padding & metrics
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => onDensityChange?.("compact")}
                    className={`flex items-center gap-3 border p-3.5 text-left transition-colors ${
                      density === "compact"
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(235,115,26,0.15)]"
                        : "border-border bg-secondary/15 hover:border-border/80"
                    }`}
                  >
                    <Sliders className="h-5 w-5 text-primary" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">Compact Terminal</div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        Dense tactical rows for high-volume threat monitoring
                      </div>
                    </div>
                  </button>
                </div>
              </div>

              {/* Visual & Auditory Controls */}
              <div className="divide-y divide-border border border-border bg-secondary/10">
                <div className="flex items-center justify-between p-3.5">
                  <div>
                    <div className="font-mono text-xs font-semibold text-foreground">
                      CRT Scanline Shading
                    </div>
                    <div className="mono-label text-[9px] text-muted-foreground">
                      Displays subtle raster line texture across charts and HUD panels
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={toggleScanlines}
                    className={`border px-3 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                      scanlines
                        ? "border-signal bg-signal/15 text-signal"
                        : "border-border text-muted-foreground"
                    }`}
                  >
                    {scanlines ? "Enabled" : "Disabled"}
                  </button>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 p-3.5">
                  <div>
                    <div className="font-mono text-xs font-semibold text-foreground flex items-center gap-2">
                      {audioAlerts ? <Volume2 className="h-3.5 w-3.5 text-primary" /> : <VolumeX className="h-3.5 w-3.5 text-muted-foreground" />}
                      Critical Alert Audio Synthesizer
                    </div>
                    <div className="mono-label text-[9px] text-muted-foreground">
                      Plays a low-latency synthesized frequency ping when critical threats arrive
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={playTacticalChime}
                      className="border border-border bg-secondary/50 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-foreground hover:border-primary/60 transition-colors"
                    >
                      Test Ping
                    </button>
                    <button
                      type="button"
                      onClick={toggleAudioAlerts}
                      className={`border px-3 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                        audioAlerts
                          ? "border-signal bg-signal/15 text-signal"
                          : "border-border text-muted-foreground"
                      }`}
                    >
                      {audioAlerts ? "Active" : "Muted"}
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* TAB 4: TELEMETRY */}
          {activeTab === "telemetry" && (
            <motion.div
              key="tab-telemetry"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 }}
              className="space-y-6"
            >
              <div>
                <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-primary">
                  Stream Transport & Ingestion Pipeline
                </h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Configure live event ingestion protocol and buffer behaviors.
                </p>
              </div>

              {/* Stream Transport Selector */}
              <div className="space-y-2">
                <div className="mono-label text-[10px] text-muted-foreground">TRANSPORT PROTOCOL</div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <button
                    type="button"
                    onClick={() => handleTransportChange("websocket")}
                    className={`flex items-start gap-3 border p-3.5 text-left transition-colors ${
                      streamTransport === "websocket"
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(235,115,26,0.15)]"
                        : "border-border bg-secondary/15 hover:border-border/80"
                    }`}
                  >
                    <Radio className="mt-0.5 h-4 w-4 text-primary" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        WebSocket Stream (Recommended)
                      </div>
                      <div className="mono-label mt-1 text-[9px] text-muted-foreground">
                        Full-duplex /api/v1/stream/ws with heartbeats and sub-10ms delivery
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleTransportChange("sse")}
                    className={`flex items-start gap-3 border p-3.5 text-left transition-colors ${
                      streamTransport === "sse"
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(235,115,26,0.15)]"
                        : "border-border bg-secondary/15 hover:border-border/80"
                    }`}
                  >
                    <Radio className="mt-0.5 h-4 w-4 text-primary" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        Server-Sent Events (SSE Fallback)
                      </div>
                      <div className="mono-label mt-1 text-[9px] text-muted-foreground">
                        HTTP /api/v1/stream/token for restricted corporate proxies
                      </div>
                    </div>
                  </button>
                </div>
              </div>

              {/* Threat Level Filter Threshold */}
              <div className="space-y-2">
                <div className="mono-label text-[10px] text-muted-foreground">ALERT NOTIFICATION LEVEL</div>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { id: "all", label: "All Severities" },
                    { id: "high_critical", label: "High & Critical" },
                    { id: "critical_only", label: "Critical Only" },
                  ].map((lvl) => (
                    <button
                      key={lvl.id}
                      type="button"
                      onClick={() => handleThresholdChange(lvl.id)}
                      className={`border px-3 py-2 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                        alertThreshold === lvl.id
                          ? "border-primary bg-primary/15 text-primary"
                          : "border-border bg-secondary/20 text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {lvl.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Stream Status Card */}
              <div className="border border-border bg-secondary/10 p-4">
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <div className="mono-label text-[9px] text-muted-foreground">RING BUFFER CAPACITY</div>
                    <div className="mt-1 font-mono text-base text-foreground">200 Alerts</div>
                  </div>
                  <div>
                    <div className="mono-label text-[9px] text-muted-foreground">EVENT REPLAY PACE</div>
                    <div className="mt-1 font-mono text-base text-signal">Realtime 1.0x</div>
                  </div>
                  <div>
                    <div className="mono-label text-[9px] text-muted-foreground">SOCKET LATENCY</div>
                    <div className="mt-1 font-mono text-base text-primary">&lt; 12ms</div>
                  </div>
                  <div>
                    <div className="mono-label text-[9px] text-muted-foreground">DATA FRESHNESS</div>
                    <div className="mt-1 font-mono text-base text-signal">Synchronized</div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* TAB 5: DIAGNOSTICS */}
          {activeTab === "diagnostics" && (
            <motion.div
              key="tab-diagnostics"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 }}
              className="space-y-6"
            >
              <div>
                <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-primary">
                  Pipeline & Inference Diagnostics
                </h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Verification receipts for active machine learning models and semantic retrieval indices.
                </p>
              </div>

              <div className="divide-y divide-border border border-border bg-card">
                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <span className="h-2 w-2 rounded-full bg-signal animate-blink" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        Fast-Tier ML Classifier (LightGBM)
                      </div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        Model: booster_v1.0.0 // Checksum: SHA-256 Verified // Latency: 1.2ms
                      </div>
                    </div>
                  </div>
                  <span className="border border-signal/60 bg-signal/10 px-2 py-0.5 font-mono text-[9px] text-signal">
                    ONLINE
                  </span>
                </div>

                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <span className="h-2 w-2 rounded-full bg-signal animate-blink" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        RAG Vector Retrieval Engine (miniLM-L6)
                      </div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        Index: 384-dimensional embeddings // Normalized cosine search
                      </div>
                    </div>
                  </div>
                  <span className="border border-signal/60 bg-signal/10 px-2 py-0.5 font-mono text-[9px] text-signal">
                    ONLINE
                  </span>
                </div>

                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <span className="h-2 w-2 rounded-full bg-signal animate-blink" />
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        Deterministic Rule Engine
                      </div>
                      <div className="mono-label text-[9px] text-muted-foreground">
                        Active Rules: In-memory evaluation on every ingress alert
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onNavigate?.("rules")}
                    className="flex items-center gap-1 font-mono text-[10px] text-primary hover:underline"
                  >
                    View Rules <ExternalLink className="h-3 w-3" />
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={() => onNavigate?.("health")}
                  className="flex items-center gap-2 border border-border bg-secondary/20 px-3.5 py-2 font-mono text-xs text-foreground hover:border-primary/60 hover:text-primary transition-colors"
                >
                  <Zap className="h-3.5 w-3.5 text-primary" />
                  Inspect External Dependencies
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate?.("audit-logs")}
                  className="flex items-center gap-2 border border-border bg-secondary/20 px-3.5 py-2 font-mono text-xs text-foreground hover:border-primary/60 hover:text-primary transition-colors"
                >
                  <Fingerprint className="h-3.5 w-3.5 text-primary" />
                  Review Security Audit Logs
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
