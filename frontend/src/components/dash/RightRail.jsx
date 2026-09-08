import { useEffect, useMemo, useState } from "react";
import { motion } from "motion/react";
import { Activity, ShieldAlert, Cpu, ArrowUpRight, Filter, ChevronRight } from "lucide-react";
import { PIPELINE_NODES } from "../../lib/flare-data.js";

const API_BASE = import.meta.env.VITE_API_BASE || "";

function useRailMetrics() {
  const [rail, setRail] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const token = localStorage.getItem("flare_token");
        const res = await fetch(`${API_BASE}/api/v1/metrics/rail`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const json = await res.json();
        if (!cancelled) setRail(json.data || json);
      } catch {
        /* fallback empty state */
      }
    };
    load();
    const id = setInterval(load, 60000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return rail;
}

function pad2(value) {
  return String(value ?? 0).padStart(2, "0");
}

/* ========================================================================= */
/* 1. Telemetry Velocity Cadence (Replaces the generic crypto wave)           */
/* ========================================================================= */
export function TelemetryVelocity({ velocity, forecast }) {
  const [hoverIdx, setHoverIdx] = useState(null);

  const samples = useMemo(() => velocity?.samples || [], [velocity]);
  const rates = useMemo(() => samples.map((s) => s.alerts_per_minute), [samples]);

  const maxRate = useMemo(() => Math.max(...rates, 1), [rates]);
  const nowVal = velocity?.now_per_min ?? 0;
  const peak = velocity?.peak_per_min ?? (rates.length ? Math.max(...rates) : 0);
  const windowLabel = velocity ? `${Math.round(velocity.window_minutes)}m` : "60m";

  const forecastLabel =
    forecast?.change_pct == null
      ? "--"
      : `${forecast.change_pct > 0 ? "+" : ""}${forecast.change_pct}%`;

  // Provide at least 24 bars for a clean visual cadence grid
  const bars = useMemo(() => {
    if (samples.length >= 20) return samples.slice(-28);
    // If fewer samples are available early on, pad gracefully
    const padCount = 28 - samples.length;
    const padding = Array.from({ length: Math.max(0, padCount) }, () => ({
      at: null,
      alerts_per_minute: 0,
    }));
    return [...padding, ...samples];
  }, [samples]);

  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3.5 bg-white/[0.015]">
        <span className="flex items-center gap-2 font-sans text-xs font-semibold uppercase tracking-wider text-white">
          <Activity className="h-3.5 w-3.5 text-white" /> Ingestion stream
        </span>
        <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-400 font-semibold">
          {forecastLabel} vs 1h
        </span>
      </div>

      {/* KPI Rate Block */}
      <div className="px-5 pt-4">
        <div className="flex items-baseline justify-between">
          <div className="flex items-baseline gap-2">
            <span className="font-sans text-2xl font-bold tracking-tight text-white">{nowVal}</span>
            <span className="font-sans text-xs text-zinc-400">events / min</span>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Active stream</span>
          </div>
        </div>

        {/* Hover Inspector Subtitle */}
        <div className="mt-1 flex items-center justify-between text-[11px] font-sans text-zinc-400 min-h-[18px]">
          <span>
            {hoverIdx !== null && bars[hoverIdx]?.at
              ? `${bars[hoverIdx].alerts_per_minute} events at ${new Date(bars[hoverIdx].at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
              : "60-min window cadence"}
          </span>
          <span className="font-mono text-zinc-400 text-[10px]">
            Peak <span className="text-white font-medium">{peak}</span>/m
          </span>
        </div>
      </div>

      {/* Discrete Cadence Histogram Bars */}
      <div className="px-5 pt-3 pb-4">
        <div className="flex h-20 items-end gap-1 rounded-xl border border-white/[0.04] bg-black/40 p-2.5">
          {bars.map((item, idx) => {
            const val = item.alerts_per_minute;
            const pct = Math.max(0.08, val / maxRate);
            const isHovered = hoverIdx === idx;
            const isLast = idx === bars.length - 1;

            return (
              <div
                key={idx}
                className="group relative flex-1 h-full flex items-end cursor-pointer"
                onMouseEnter={() => setHoverIdx(idx)}
                onMouseLeave={() => setHoverIdx(null)}
              >
                <motion.div
                  className={`w-full rounded-sm transition-all duration-200 ${
                    isHovered
                      ? "bg-white shadow-[0_0_10px_rgba(255,255,255,0.8)]"
                      : isLast
                        ? "bg-white shadow-[0_0_8px_rgba(255,255,255,0.3)]"
                        : val > 0
                          ? "bg-white/30 hover:bg-white/60"
                          : "bg-white/[0.06]"
                  }`}
                  style={{ height: `${pct * 100}%` }}
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* Summary Footer */}
      <div className="grid grid-cols-3 divide-x divide-white/[0.06] border-t border-white/[0.06] bg-white/[0.01]">
        {[
          ["CURRENT", `${nowVal}/m`],
          ["PEAK", `${peak}/m`],
          ["WINDOW", windowLabel],
        ].map(([k, v]) => (
          <div key={k} className="px-3 py-2.5 text-center">
            <div className="font-mono text-[9px] uppercase tracking-wider text-zinc-500">{k}</div>
            <div className="font-mono text-xs text-white font-semibold mt-0.5">{v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ========================================================================= */
/* 2. Attack Surface Intel (Replaces the 3D rotating planetary gimbal)       */
/* ========================================================================= */
export function AttackSurfaceIntel({ surface, onFilterChange }) {
  const nodes = useMemo(() => {
    const raw = surface?.nodes || [];
    // Sort top threat actors by alert count
    return [...raw].sort((a, b) => (b.alert_count ?? 0) - (a.alert_count ?? 0)).slice(0, 4);
  }, [surface]);

  const maxNodeCount = useMemo(() => {
    return Math.max(...nodes.map((n) => n.alert_count || 1), 1);
  }, [nodes]);

  const getSeverityStyle = (sev) => {
    switch (sev?.toLowerCase()) {
      case "critical":
        return "border-red-500/40 bg-red-500/15 text-red-400";
      case "high":
        return "border-amber-500/40 bg-amber-500/15 text-amber-400";
      case "medium":
        return "border-yellow-400/40 bg-yellow-400/15 text-yellow-300";
      default:
        return "border-white/20 bg-white/10 text-zinc-300";
    }
  };

  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3.5 bg-white/[0.015]">
        <span className="flex items-center gap-2 font-sans text-xs font-semibold uppercase tracking-wider text-white">
          <ShieldAlert className="h-3.5 w-3.5 text-white" /> Attack surface intel
        </span>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-destructive/30 bg-destructive/10 px-2.5 py-0.5 font-mono text-[10px] font-semibold text-destructive">
          <span className="h-1.5 w-1.5 rounded-full bg-destructive animate-pulse" />
          {surface?.hot ?? 0} HOT
        </span>
      </div>

      {/* Perimeter KPI Matrix */}
      <div className="px-5 pt-3.5 pb-2">
        <div className="grid grid-cols-3 gap-2 rounded-xl border border-white/[0.06] bg-black/40 p-2.5 text-center">
          <div>
            <div className="font-mono text-[9px] uppercase tracking-wider text-zinc-500">Origins</div>
            <div className="mt-0.5 font-mono text-xs font-semibold text-white">
              {pad2(surface?.origins)}
            </div>
          </div>
          <div className="border-x border-white/[0.06]">
            <div className="font-mono text-[9px] uppercase tracking-wider text-zinc-500">Paths</div>
            <div className="mt-0.5 font-mono text-xs font-semibold text-white">
              {pad2(surface?.paths)}
            </div>
          </div>
          <div>
            <div className="font-mono text-[9px] uppercase tracking-wider text-zinc-500">Subnet</div>
            <div className="mt-0.5 font-mono text-[11px] font-semibold text-zinc-300 truncate px-1" title={surface?.dominant_subnet}>
              {surface?.dominant_subnet ? surface.dominant_subnet.split("/")[0] : "192.168.0"}
            </div>
          </div>
        </div>
      </div>

      {/* Top Ingress Threat Actors List */}
      <div className="px-5 py-2">
        <div className="mb-2 flex items-center justify-between text-[11px] font-sans text-zinc-400">
          <span className="font-semibold text-white">Top ingress actors</span>
          <span className="text-[10px] text-zinc-500 font-mono">click to filter</span>
        </div>

        <div className="space-y-2">
          {nodes.length > 0 ? (
            nodes.map((actor, idx) => {
              const loadPct = Math.min(100, Math.max(12, ((actor.alert_count || 1) / maxNodeCount) * 100));
              const isCrit = actor.severity === "critical";

              return (
                <div
                  key={actor.src_ip || idx}
                  onClick={() => onFilterChange?.({ search: actor.src_ip })}
                  title={`Filter alert feed for ${actor.src_ip}`}
                  className="group relative rounded-xl border border-white/[0.06] bg-white/[0.02] p-2.5 transition-all duration-200 hover:border-white/30 hover:bg-white/[0.05] cursor-pointer"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono text-xs font-semibold text-white tracking-tight group-hover:text-white transition-colors truncate">
                        {actor.src_ip}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-sans truncate">
                        // {actor.attack_type || "anomaly"}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className={`rounded px-1.5 py-0.2 font-mono text-[9px] uppercase font-semibold border ${getSeverityStyle(actor.severity)}`}>
                        {actor.severity}
                      </span>
                      <span className="font-mono text-[11px] text-zinc-300 font-medium">
                        {actor.alert_count}
                      </span>
                      <ChevronRight className="h-3 w-3 text-zinc-500 group-hover:text-white transition-transform group-hover:translate-x-0.5" />
                    </div>
                  </div>

                  {/* Intensity Meter Bar */}
                  <div className="mt-2 h-1 w-full rounded-full bg-white/[0.06] overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        isCrit ? "bg-red-500" : "bg-white"
                      }`}
                      style={{ width: `${loadPct}%` }}
                    />
                  </div>
                </div>
              );
            })
          ) : (
            <div className="py-4 text-center font-sans text-xs text-zinc-500">
              No anomalous ingress vectors detected in active window.
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="mt-2 flex justify-between border-t border-white/[0.06] px-5 py-2.5 bg-white/[0.01] font-sans text-xs text-zinc-400">
        <span>{surface ? `${surface.window_minutes}m analysis window` : "60m window"}</span>
        <span className="text-emerald-400 font-medium font-mono">Perimeter monitored</span>
      </div>
    </div>
  );
}

/* ========================================================================= */
/* 3. Pipeline Activity (Refined & Polish)                                   */
/* ========================================================================= */
export function AgentActivity({ pipeline }) {
  const items = useMemo(() => {
    const byName = new Map((pipeline?.nodes || []).map((n) => [n.name, n]));
    return PIPELINE_NODES.map((name) => {
      const node = byName.get(name);
      return { name, state: node?.state ?? "--", load: node?.load ?? 0 };
    });
  }, [pipeline]);

  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3.5 bg-white/[0.015]">
        <span className="flex items-center gap-2 font-sans text-xs font-semibold uppercase tracking-wider text-white">
          <Cpu className="h-3.5 w-3.5 text-white" /> Pipeline activity
        </span>
        <ArrowUpRight className="h-3.5 w-3.5 text-zinc-500" />
      </div>
      <div className="space-y-3.5 px-5 py-4">
        {items.map((a, i) => (
          <div key={a.name}>
            <div className="flex items-center justify-between font-sans text-xs">
              <span className="capitalize text-zinc-200 font-medium">{a.name}</span>
              <span className={a.state === "active" ? "text-emerald-400 font-semibold" : "text-white font-semibold"}>
                {a.state}
              </span>
            </div>
            <div className="mt-1.5 h-1.5 w-full rounded-full bg-white/[0.06] overflow-hidden">
              <motion.div
                className={`h-full rounded-full ${
                  a.state === "active"
                    ? "bg-emerald-400 shadow-[0_0_8px_rgba(74,222,128,0.4)]"
                    : "bg-zinc-400 shadow-[0_0_8px_rgba(255,255,255,0.2)]"
                }`}
                initial={{ width: 0 }}
                animate={{ width: `${a.load * 100}%` }}
                transition={{ duration: 1, delay: i * 0.12, ease: "easeOut" }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ========================================================================= */
/* Right Rail Orchestrator                                                   */
/* ========================================================================= */
export function RightRail({ onFilterChange }) {
  const rail = useRailMetrics();

  return (
    <div className="space-y-4">
      {/* 1. Telemetry Velocity & Cadence */}
      <TelemetryVelocity velocity={rail?.signal_velocity} forecast={rail?.threat_forecast} />

      {/* 2. Attack Surface & Threat Actors */}
      <AttackSurfaceIntel surface={rail?.attack_surface} onFilterChange={onFilterChange} />

      {/* 3. Pipeline Activity */}
      <AgentActivity pipeline={rail?.pipeline_activity} />
    </div>
  );
}

// Backward compatibility alias exports
export const SignalVelocity = TelemetryVelocity;
export const AttackSurface = AttackSurfaceIntel;
