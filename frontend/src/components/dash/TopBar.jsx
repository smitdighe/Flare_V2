import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Search, Command, Settings, LogOut, Wifi, Zap } from "lucide-react";

// FE-15 (PLAN §3.3 / §3.1). The ticker used to cycle a 3.6-second carousel
// through whichever high-severity alerts were in the browser buffer. PLAN §3.1
// asks for one thing — the CURRENT highest-severity alert — and
// `GET /metrics/overview` resolves that over the whole alerts table, under the
// active filter, with recency breaking ties inside the top severity.
const NO_TICKER = { severity: "low", signature: "no active threats", dest_ip: "--" };

export function TopBar({ ticker, paused, onTogglePaused, onCommand, onLogout, connectionStatus }) {
  const [live, setLive] = useState(!paused);

  useEffect(() => {
    setLive(!paused);
  }, [paused]);

  const current = ticker || NO_TICKER;

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/85 px-4 backdrop-blur-xl">
      <div className="hidden min-w-0 flex-1 items-center gap-3 border-l border-border pl-4 md:flex">
        <motion.div
          key={current.id || "empty"}
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="flex min-w-0 items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em]"
        >
          <span className={current.severity === "critical" ? "text-destructive" : "text-primary"}>
            {current.severity}
          </span>
          <span className="text-muted-foreground">//</span>
          <span className="truncate text-foreground">{current.signature}</span>
          <span className="text-muted-foreground">against {current.dest_ip}</span>
        </motion.div>
      </div>

      <button
        type="button"
        onClick={onCommand}
        className="group hidden items-center gap-2 border border-input bg-card/50 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground transition-colors hover:border-primary/60 hover:text-foreground lg:flex"
      >
        <Search className="h-3.5 w-3.5 transition-colors group-hover:text-primary" />
        search ip / id / signature
        <span className="ml-6 flex items-center gap-1 border border-border px-1.5 py-0.5 text-[9px]">
          <Command className="h-2.5 w-2.5" />K
        </span>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <motion.button
          type="button"
          whileTap={{ scale: 0.94 }}
          onClick={onTogglePaused}
          className={`flex items-center gap-2 border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] transition-colors ${
            live
              ? "border-signal/60 bg-signal/10 text-signal"
              : "border-border text-muted-foreground hover:text-foreground"
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${live ? "animate-blink bg-signal" : "bg-muted-foreground"}`} />
          {live ? "live" : "paused"}
        </motion.button>

        <span className="hidden items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-primary sm:flex">
          <Wifi className="h-3 w-3" /> {connectionStatus || "ws"}
        </span>

        <button
          type="button"
          className="flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground"
        >
          <Settings className="h-3 w-3" /> <span className="hidden sm:inline">settings</span>
        </button>

        <button
          type="button"
          onClick={onLogout}
          className="flex items-center gap-1.5 border border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground transition-colors hover:border-destructive/60 hover:text-destructive"
        >
          <LogOut className="h-3 w-3" /> <span className="hidden sm:inline">logout</span>
        </button>
      </div>

      <motion.span
        className="pointer-events-none absolute bottom-0 left-0 h-px bg-primary"
        animate={{ width: ["0%", "100%"] }}
        transition={{ duration: 3.6, repeat: Infinity, ease: "linear" }}
      >
        <Zap className="hidden" />
      </motion.span>
    </header>
  );
}
