import { motion } from "motion/react";
import { Search, Command, Settings, LogOut } from "lucide-react";

// FE-15 (PLAN §3.3 / §3.1). The ticker used to cycle a 3.6-second carousel
// through whichever high-severity alerts were in the browser buffer. PLAN §3.1
// asks for one thing — the CURRENT highest-severity alert — and
// `GET /metrics/overview` resolves that over the whole alerts table, under the
// active filter, with recency breaking ties inside the top severity.
const NO_TICKER = { severity: "low", signature: "no active threats", dest_ip: "--" };

export function TopBar({ ticker, onCommand, onLogout, onNavigate, activeSection }) {

  const current = ticker || NO_TICKER;

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-white/10 bg-black/75 px-4 backdrop-blur-2xl shadow-[inset_0_-1px_1px_rgba(255,255,255,0.06),0_12px_32px_rgba(0,0,0,0.6)]">
      <div className="hidden min-w-0 flex-1 items-center gap-3 border-l border-white/[0.06] pl-4 md:flex">
        <motion.div
          key={current.id || "empty"}
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="flex min-w-0 items-center gap-2.5 font-mono text-[11px] uppercase tracking-[0.14em]"
        >
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-medium ${
            current.severity === "critical"
              ? "bg-destructive/15 text-destructive border border-destructive/30"
              : "bg-primary/10 text-primary border border-primary/20"
          }`}>
            <span className={`h-1 w-1 rounded-full ${current.severity === "critical" ? "bg-destructive animate-pulse" : "bg-primary"}`} />
            {current.severity}
          </span>
          <span className="text-white/20">//</span>
          <span className="truncate text-foreground font-medium">{current.signature}</span>
          <span className="text-muted-foreground">against <span className="text-foreground/80">{current.dest_ip}</span></span>
        </motion.div>
      </div>

      <button
        type="button"
        onClick={onCommand}
        className="group hidden items-center gap-3 rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-1.5 font-sans text-xs text-zinc-400 backdrop-blur-md shadow-[inset_0_1px_1px_rgba(255,255,255,0.08)] transition-all hover:border-primary/40 hover:bg-white/[0.07] hover:text-white lg:flex"
      >
        <Search className="h-3.5 w-3.5 transition-colors group-hover:text-primary" />
        <span>Search IP, ID, or signature...</span>
        <span className="ml-4 flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.06] px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
          <Command className="h-2.5 w-2.5" />K
        </span>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <button
          type="button"
          onClick={() => onNavigate?.("settings")}
          className={`flex items-center gap-1.5 rounded-xl border px-3 py-1.5 font-sans text-xs font-medium transition-all ${
            activeSection === "settings"
              ? "border-primary/50 bg-primary/15 text-primary shadow-[0_0_16px_rgba(56,189,248,0.2)]"
              : "border-white/10 bg-white/[0.02] text-zinc-400 hover:border-white/20 hover:text-white"
          }`}
        >
          <Settings className="h-3.5 w-3.5" /> <span className="hidden sm:inline">Settings</span>
        </button>

        <button
          type="button"
          onClick={onLogout}
          className="flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.02] px-3 py-1.5 font-sans text-xs font-medium text-zinc-400 transition-all hover:border-destructive/40 hover:bg-destructive/10 hover:text-destructive"
        >
          <LogOut className="h-3.5 w-3.5" /> <span className="hidden sm:inline">Logout</span>
        </button>
      </div>
    </header>
  );
}
