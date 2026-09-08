import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, Plus } from "lucide-react";
import CyberSelect from "../CyberSelect.jsx";

const FILTERS = ["all", "critical", "high", "medium", "low"];

const SEVERITY_FILTER_STYLES = {
  all: {
    active: 'border-white/30 bg-white/10 text-white shadow-[0_0_14px_rgba(255,255,255,0.14)] font-semibold',
  },
  critical: {
    active: 'border-red-500/50 bg-red-500/20 text-red-400 shadow-[0_0_16px_rgba(239,68,68,0.25)] font-semibold',
  },
  high: {
    active: 'border-amber-500/50 bg-amber-500/20 text-amber-400 shadow-[0_0_16px_rgba(245,158,11,0.25)] font-semibold',
  },
  medium: {
    active: 'border-yellow-400/50 bg-yellow-400/20 text-yellow-300 shadow-[0_0_16px_rgba(250,204,21,0.25)] font-semibold',
  },
  low: {
    active: 'border-sky-400/50 bg-sky-400/20 text-sky-300 shadow-[0_0_16px_rgba(56,189,248,0.25)] font-semibold',
  },
  info: {
    active: 'border-indigo-400/50 bg-indigo-400/20 text-indigo-300 shadow-[0_0_16px_rgba(129,140,248,0.25)] font-semibold',
  },
};

const SEVERITY_FEED_STYLES = {
  critical: {
    row: 'bg-red-500/[0.06] border-l-[4px] border-l-red-500 hover:bg-red-500/[0.12]',
    badge: 'border-red-500/40 bg-red-500/20 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.2)]',
    dot: 'bg-red-500 animate-pulse shadow-[0_0_8px_#ef4444]',
    vector: 'text-red-400',
  },
  high: {
    row: 'bg-amber-500/[0.05] border-l-[4px] border-l-amber-500 hover:bg-amber-500/[0.10]',
    badge: 'border-amber-500/40 bg-amber-500/20 text-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.2)]',
    dot: 'bg-amber-500 shadow-[0_0_8px_#f59e0b]',
    vector: 'text-amber-400',
  },
  medium: {
    row: 'bg-yellow-500/[0.04] border-l-[4px] border-l-yellow-400 hover:bg-yellow-500/[0.09]',
    badge: 'border-yellow-400/40 bg-yellow-400/20 text-yellow-300 shadow-[0_0_10px_rgba(250,204,21,0.2)]',
    dot: 'bg-yellow-400 shadow-[0_0_8px_#facc15]',
    vector: 'text-yellow-300',
  },
  low: {
    row: 'bg-sky-500/[0.035] border-l-[4px] border-l-sky-400 hover:bg-sky-500/[0.08]',
    badge: 'border-sky-400/40 bg-sky-400/20 text-sky-300 shadow-[0_0_10px_rgba(56,189,248,0.2)]',
    dot: 'bg-sky-400 shadow-[0_0_8px_#38bdf8]',
    vector: 'text-sky-300',
  },
  info: {
    row: 'bg-indigo-500/[0.035] border-l-[4px] border-l-indigo-400 hover:bg-indigo-500/[0.08]',
    badge: 'border-indigo-400/40 bg-indigo-400/20 text-indigo-300 shadow-[0_0_10px_rgba(129,140,248,0.2)]',
    dot: 'bg-indigo-400 shadow-[0_0_8px_#818cf8]',
    vector: 'text-indigo-300',
  },
};

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
      <div className="relative rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)] overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] bg-white/[0.015] px-6 py-4">
          <div>
            <div className="font-sans text-base font-semibold text-white tracking-tight">Live alert feed</div>
            <div className="text-xs text-zinc-500 font-sans mt-0.5">Priority queue // {String(rows.length).padStart(3, "0")} visible</div>
          </div>
          <div className="hidden items-center gap-3 font-sans text-xs text-zinc-500 sm:flex">
            <span className="flex items-center gap-1.5">
              <kbd className="rounded-md border border-white/10 bg-white/[0.06] px-2 py-0.5 font-mono text-[10px] text-zinc-300 shadow-sm">↵ ENTER</kbd>
              <span>inspect</span>
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-white/[0.06] bg-white/[0.01] px-6 py-3.5">
          {FILTERS.map((f) => {
            const isSelected = filter === f;
            const fStyle = SEVERITY_FILTER_STYLES[f] || SEVERITY_FILTER_STYLES.all;
            return (
              <motion.button
                key={f}
                type="button"
                whileTap={{ scale: 0.95 }}
                onClick={() => setFilter(f)}
                className={`relative rounded-xl border px-3.5 py-1.5 font-sans text-xs capitalize transition-all ${
                  isSelected
                    ? fStyle.active
                    : "border-white/10 bg-white/[0.02] text-zinc-400 hover:border-white/20 hover:bg-white/[0.05] hover:text-white font-medium"
                }`}
              >
                {f === "all" ? "All signals" : f}
              </motion.button>
            );
          })}
          <CyberSelect
            className="ml-auto"
            align="right"
            prefix="VECTOR"
            value={vector}
            onChange={(val) => setVector(val)}
            options={vectors.map((v) => ({
              value: v,
              label: v === "all" ? "ALL VECTORS" : v,
            }))}
          />
        </div>

        <div className="hidden grid-cols-[1fr_0.7fr_1fr_1.4fr_1.6fr_0.8fr] gap-3 border-b border-white/[0.06] bg-white/[0.01] px-6 py-3 md:grid">
          {["signal / age", "severity", "vector", "route", "signature", "pipeline"].map((h) => (
            <span key={h} className="font-sans text-xs font-semibold uppercase tracking-wider text-zinc-400">
              {h}
            </span>
          ))}
        </div>

        <div className="divide-y divide-white/[0.04]">
          <AnimatePresence initial={false}>
            {rows.slice(0, compact ? 6 : 40).map((a, i) => {
              const sev = SEVERITY_FEED_STYLES[a.severity] || SEVERITY_FEED_STYLES.low;

              return (
                <motion.button
                  key={`${a.id}-${i}`}
                  layout
                  type="button"
                  onClick={() => handleSelect(a)}
                  initial={{ opacity: 0, x: 16 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ delay: Math.min(i * 0.03, 0.3), duration: 0.3 }}
                  className={`group grid w-full grid-cols-2 items-center gap-3 px-6 py-3.5 text-left transition-all duration-200 md:grid-cols-[1fr_0.7fr_1fr_1.4fr_1.6fr_0.8fr] ${sev.row}`}
                >
                  <span className="flex items-center gap-2.5">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${sev.dot}`} />
                    <span>
                      <span className="font-mono text-xs font-semibold text-white">
                        {a.timestamp ? new Date(a.timestamp).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : a.time}
                      </span>
                      <span className="block font-sans text-[11px] text-zinc-400">{a.ageMin || 0}m ago</span>
                    </span>
                  </span>

                  <span
                    className={`w-fit inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-sans text-[10px] font-semibold tracking-wide capitalize ${sev.badge}`}
                  >
                    <span className={`h-1.5 w-1.5 rounded-full ${sev.dot}`} />
                    {a.severity}
                  </span>

                  <span className="text-xs">
                    <span className={`font-sans font-semibold capitalize ${sev.vector}`}>{a.attack_type || a.vector}</span>
                    <span className="block font-mono text-[10px] text-zinc-400">
                      {a.protocol || a.proto}:{a.dest_port || a.port}
                    </span>
                  </span>

                  <span className="hidden font-mono text-xs md:block">
                    <span className="text-white">{a.src_ip || a.src}</span> <span className="text-zinc-500">→</span> <span className="text-white">{a.dest_ip || a.dst}</span>
                    <span className="block font-sans text-[11px] text-zinc-500">mitre {a.mitre_technique || a.mitre}</span>
                  </span>

                  <span className="hidden min-w-0 md:block">
                    <span className="block truncate font-sans text-xs font-medium text-zinc-200">{a.signature}</span>
                    <span className="font-mono text-[10px] text-zinc-500">{a.id}</span>
                  </span>

                  <span className="hidden items-center gap-2 md:flex">
                    {[0, 1, 2].map((si) => (
                      <motion.span
                        key={si}
                        className="h-2 w-2 rounded-full bg-primary"
                        animate={{ opacity: [0.3, 1, 0.3] }}
                        transition={{ duration: 1.6, repeat: Infinity, delay: si * 0.25 }}
                      />
                    ))}
                    <ArrowRight className="ml-auto h-4 w-4 text-zinc-500 transition-transform duration-300 group-hover:translate-x-1 group-hover:text-primary" />
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
