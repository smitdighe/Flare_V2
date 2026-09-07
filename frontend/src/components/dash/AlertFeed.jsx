import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, Plus } from "lucide-react";

const FILTERS = ["all", "critical", "high", "medium", "low"];

export function AlertFeed({ alerts = [], onSelect, compact = false }) {
  const [filter, setFilter] = useState("all");
  const [vector, setVector] = useState("all");

  const vectors = useMemo(() => ["all", ...new Set(alerts.map((a) => a.attack_type || a.vector).filter(Boolean))], [alerts]);
  const rows = alerts.filter(
    (a) => (filter === "all" || a.severity === filter) && (vector === "all" || (a.attack_type || a.vector) === vector),
  );

  // FE-18: this used to drive a local AlertDrawer as well. That drawer was
  // unreachable and hardcoded retired model IDs and fabricated latencies, so it
  // is gone; selection now only notifies the parent, which is the behaviour
  // anything rendering this component actually consumes.
  const handleSelect = (alert) => {
    onSelect?.(alert);
  };

  return (
    <>
      <div className="panel scanline relative">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div>
            <div className="mono-label">priority queue // {String(rows.length).padStart(3, "0")} visible</div>
            <div className="font-display mt-0.5 text-xl leading-none">Live alert feed</div>
          </div>
          <div className="mono-label flex items-center gap-4">
            <span className="hidden sm:inline">
              <span className="text-primary">enter</span> inspect
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3">
          {FILTERS.map((f) => (
            <motion.button
              key={f}
              type="button"
              whileTap={{ scale: 0.95 }}
              onClick={() => setFilter(f)}
              className={`relative border px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] transition-colors ${
                filter === f
                  ? "border-primary bg-primary text-primary-foreground"
                  : "border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
              }`}
            >
              {f === "all" ? "all signals" : `[ ] ${f}`}
            </motion.button>
          ))}
          <select
            value={vector}
            onChange={(e) => setVector(e.target.value)}
            className="ml-auto border border-input bg-card px-2 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-foreground outline-none focus:border-primary"
          >
            {vectors.map((v) => (
              <option key={v} value={v}>
                vector: {v}
              </option>
            ))}
          </select>
        </div>

        <div className="hidden grid-cols-[1fr_0.7fr_1fr_1.4fr_1.6fr_0.8fr] gap-3 border-b border-border px-4 py-2 md:grid">
          {["signal / age", "severity", "vector", "route", "signature", "pipeline"].map((h) => (
            <span key={h} className="mono-label text-[9px]">
              {h}
            </span>
          ))}
        </div>

        <div className="divide-y divide-border">
          <AnimatePresence initial={false}>
            {rows.slice(0, compact ? 6 : 40).map((a, i) => {
              const sev = {
                critical: { text: "text-destructive", bg: "bg-destructive/15", ring: "border-destructive/50" },
                high: { text: "text-primary", bg: "bg-primary/15", ring: "border-primary/50" },
                medium: { text: "text-primary-glow", bg: "bg-primary-glow/10", ring: "border-primary-glow/40" },
                low: { text: "text-signal", bg: "bg-signal/10", ring: "border-signal/40" },
              }[a.severity] || { text: "text-muted-foreground", bg: "bg-muted", ring: "border-border" };

              return (
                <motion.button
                  key={a.id}
                  layout
                  type="button"
                  onClick={() => handleSelect(a)}
                  initial={{ opacity: 0, x: 16 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ delay: Math.min(i * 0.03, 0.3), duration: 0.3 }}
                  whileHover={{ backgroundColor: "color-mix(in oklab, var(--accent) 45%, transparent)" }}
                  className="group grid w-full grid-cols-2 items-center gap-3 px-4 py-3 text-left md:grid-cols-[1fr_0.7fr_1fr_1.4fr_1.6fr_0.8fr]"
                >
                  <span className="flex items-center gap-2">
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sev.text} bg-current`} />
                    <span className="font-mono text-xs">
                      {a.timestamp ? new Date(a.timestamp).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : a.time}
                      <span className="mono-label block text-[9px]">{a.ageMin || 0}m ago</span>
                    </span>
                  </span>

                  <span
                    className={`w-fit border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.16em] ${sev.text} ${sev.ring} ${sev.bg}`}
                  >
                    {a.severity}
                  </span>

                  <span className="font-mono text-xs text-primary">
                    {a.attack_type || a.vector}
                    <span className="mono-label block text-[9px] normal-case">
                      {a.protocol || a.proto}:{a.dest_port || a.port}
                    </span>
                  </span>

                  <span className="hidden font-mono text-xs md:block">
                    {a.src_ip || a.src} <span className="text-primary">→</span> {a.dest_ip || a.dst}
                    <span className="mono-label block text-[9px]">mitre {a.mitre_technique || a.mitre}</span>
                  </span>

                  <span className="hidden min-w-0 md:block">
                    <span className="block truncate font-mono text-xs">{a.signature}</span>
                    <span className="mono-label text-[9px]">{a.id}</span>
                  </span>

                  <span className="hidden items-center gap-1.5 md:flex">
                    {[0, 1, 2].map((si) => (
                      <motion.span
                        key={si}
                        className="h-2.5 w-2.5 bg-primary"
                        animate={{ opacity: [0.25, 1, 0.25] }}
                        transition={{ duration: 1.6, repeat: Infinity, delay: si * 0.25 }}
                      />
                    ))}
                    <ArrowRight className="ml-auto h-3.5 w-3.5 text-muted-foreground transition-transform duration-300 group-hover:translate-x-1 group-hover:text-primary" />
                  </span>
                </motion.button>
              );
            })}
          </AnimatePresence>
        </div>
      </div>
    </>
  );
}
