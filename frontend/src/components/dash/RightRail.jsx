import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowUpRight, Cpu, Waves, Orbit } from "lucide-react";
import { PIPELINE_NODES } from "../../lib/flare-data.js";

const API_BASE = import.meta.env.VITE_API_BASE || "";

// FE-14 (PLAN §3.3). All four panels below used to compute their numbers from
// whatever alerts happened to be in the browser buffer, or from literals
// (`+18.4%`, the x62 scale, `60m`, `3 hot`, `08 origins // 08 paths`,
// `10.24.0.0/16`, the four pipeline loads). Every one of those has a real
// producer at `GET /metrics/rail`, and this is the reader. There is no DEV
// branch: PLAN I9 forbids seeded data in every environment, development
// included.
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
      } catch { /* the panels render their empty state */ }
    };
    load();
    // The signal-velocity series is sampled once a minute by the scheduler, so
    // polling faster than that would re-fetch a series that cannot have moved.
    const id = setInterval(load, 60000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return rail;
}

function pad2(value) {
  return String(value ?? 0).padStart(2, "0");
}

export function SignalVelocity({ velocity, forecast }) {
  const values = useMemo(
    () => (velocity?.samples || []).map((s) => s.alerts_per_minute),
    [velocity],
  );
  // Plot space is 0..1 of the panel height. The old code multiplied an
  // invented series by 62 to get a number to print; here the printed numbers
  // are the measured rates and only the DRAWING is normalized.
  const data = useMemo(() => {
    const max = Math.max(...values, 1);
    return values.map((v) => 0.06 + (v / max) * 0.94);
  }, [values]);

  const [hover, setHover] = useState(null);
  const W = 300;
  const H = 96;
  const step = data.length > 1 ? W / (data.length - 1) : W;
  const pts = data.map((v, i) => [i * step, H - v * H]);
  const line = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${W},${H} L0,${H} Z`;

  const nowVal = velocity?.now_per_min ?? 0;
  const peak = velocity?.peak_per_min ?? 0;
  const windowLabel = velocity ? `${Math.round(velocity.window_minutes)}m` : "--";
  // A ratio against an empty previous window has no value (PLAN D8). The
  // backend returns null and says why; a dash is the honest render.
  const forecastLabel =
    forecast?.change_pct == null
      ? "--"
      : `${forecast.change_pct > 0 ? "+" : ""}${forecast.change_pct}%`;

  return (
    <div className="panel scanline relative overflow-hidden">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <span className="mono-label flex items-center gap-2">
          <Waves className="h-3 w-3 text-primary" /> threat forecast
        </span>
        <span className="mono-label text-signal">{forecastLabel}</span>
      </div>

      <div className="px-4 pt-3">
        <div className="font-display text-2xl leading-none">Signal velocity</div>
        <div className="mono-label mt-1.5 flex justify-between">
          <span>{hover !== null ? `${values[hover]} events / min` : "live window"}</span>
          <span className="text-primary">peak {peak} / min</span>
        </div>
      </div>

      <svg viewBox={`0 0 ${W} ${H}`} className="mt-2 h-28 w-full" preserveAspectRatio="none">
        <defs>
          <linearGradient id="fv-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.55" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="fv-stroke" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--primary-glow)" />
            <stop offset="100%" stopColor="var(--primary)" />
          </linearGradient>
        </defs>

        {[0.25, 0.5, 0.75].map((g) => (
          <line key={g} x1="0" x2={W} y1={H * g} y2={H * g} stroke="var(--border)" strokeWidth="0.5" />
        ))}

        {/* Two samples are the minimum a line can be drawn between. Below that
            the grid renders alone rather than a flat line that would read as a
            measured quiet period. */}
        {data.length > 1 && (
          <>
            <motion.path
              d={area}
              fill="url(#fv-fill)"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 1.2 }}
            />
            <motion.path
              d={line}
              fill="none"
              stroke="url(#fv-stroke)"
              strokeWidth="1.6"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 1.6, ease: "easeInOut" }}
            />
          </>
        )}

        {pts.map(([x, y], i) => (
          <g key={i}>
            <rect
              x={x - step / 2}
              y={0}
              width={step}
              height={H}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            />
            {hover === i && (
              <>
                <line x1={x} x2={x} y1={0} y2={H} stroke="var(--primary)" strokeWidth="0.6" />
                <circle cx={x} cy={y} r="2.6" fill="var(--primary-glow)" />
              </>
            )}
          </g>
        ))}

        {pts.length > 1 && (
          <motion.circle
            r="3"
            fill="var(--primary)"
            animate={{ cx: pts.map(([x]) => x), cy: pts.map(([, y]) => y) }}
            transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
          />
        )}
      </svg>

      <div className="grid grid-cols-3 divide-x divide-border border-t border-border">
        {[
          ["now", `${nowVal}/m`],
          ["peak", `${peak}/m`],
          ["window", windowLabel],
        ].map(([k, v]) => (
          <div key={k} className="px-3 py-2.5">
            <div className="mono-label text-[9px]">{k}</div>
            <div className="font-mono text-xs text-primary">{v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AttackSurface({ surface }) {
  const nodes = useMemo(
    () =>
      (surface?.nodes || []).slice(0, 8).map((n, i) => {
        const angle = (i / 8) * Math.PI * 2;
        const radius = 34 + (i % 3) * 21;
        return {
          id: n.src_ip,
          ip: n.src_ip,
          vector: n.attack_type,
          severity: n.severity,
          count: n.alert_count,
          x: 100 + Math.cos(angle) * radius,
          y: 100 + Math.sin(angle) * radius,
        };
      }),
    [surface],
  );
  const [active, setActive] = useState(null);
  const activeNode = nodes.find((n) => n.id === active);

  return (
    <div className="panel relative overflow-hidden">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <span className="mono-label flex items-center gap-2">
          <Orbit className="h-3 w-3 text-primary" /> attack surface
        </span>
        <span className="mono-label text-destructive">{surface?.hot ?? 0} hot</span>
      </div>

      <div className="relative px-2 py-2">
        <svg viewBox="0 0 200 200" className="h-56 w-full">
          <defs>
            <radialGradient id="core" cx="50%" cy="50%">
              <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.9" />
              <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
            </radialGradient>
          </defs>

          {[34, 55, 76, 94].map((r, i) => (
            <motion.circle
              key={r}
              cx="100"
              cy="100"
              r={r}
              fill="none"
              stroke="var(--border)"
              strokeDasharray={i % 2 ? "2 6" : "1 4"}
              style={{ transformOrigin: "100px 100px" }}
              animate={{ rotate: i % 2 ? 360 : -360 }}
              transition={{ duration: 40 + i * 14, repeat: Infinity, ease: "linear" }}
            />
          ))}

          <motion.circle
            cx="100"
            cy="100"
            r="30"
            fill="url(#core)"
            animate={{ opacity: [0.4, 0.9, 0.4], scale: [0.9, 1.1, 0.9] }}
            transition={{ duration: 4, repeat: Infinity }}
            style={{ transformOrigin: "100px 100px" }}
          />

          {nodes.map((n) => (
            <line
              key={`l-${n.id}`}
              x1="100"
              y1="100"
              x2={n.x}
              y2={n.y}
              stroke={active === n.id ? "var(--primary)" : "var(--border)"}
              strokeWidth={active === n.id ? 1 : 0.5}
            />
          ))}

          {nodes.map((n, i) => {
            const hot = n.severity === "critical" || n.severity === "high";
            return (
              <g
                key={n.id}
                onMouseEnter={() => setActive(n.id)}
                onMouseLeave={() => setActive(null)}
                className="cursor-pointer"
              >
                <motion.circle
                  cx={n.x}
                  cy={n.y}
                  r={active === n.id ? 9 : 6}
                  fill={hot ? "var(--primary)" : "var(--muted-foreground)"}
                  fillOpacity={0.18}
                  animate={{ r: [5, 11, 5] }}
                  transition={{ duration: 3, repeat: Infinity, delay: i * 0.3 }}
                />
                <circle
                  cx={n.x}
                  cy={n.y}
                  r="3"
                  fill={hot ? "var(--primary)" : "var(--foreground)"}
                />
              </g>
            );
          })}

          <text x="100" y="103" textAnchor="middle" className="fill-foreground font-mono" fontSize="7">
            {surface?.dominant_subnet || "--"}
          </text>
        </svg>

        <AnimatePresence>
          {active && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              className="absolute inset-x-3 bottom-3 border border-primary/40 bg-popover/95 px-3 py-2 backdrop-blur"
            >
              <div className="font-mono text-xs text-primary">
                {activeNode?.ip}
              </div>
              <div className="mono-label text-[9px]">
                {activeNode?.vector} // {activeNode?.count} linked
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="mono-label flex justify-between border-t border-border px-4 py-2.5">
        <span>{pad2(surface?.origins)} origins // {pad2(surface?.paths)} paths</span>
        <span className="text-signal">{surface ? `${surface.window_minutes}m window` : "--"}</span>
      </div>
    </div>
  );
}

export function AgentActivity({ pipeline }) {
  // The graph has seven nodes; this panel has room for four and the frozen
  // layout is not ours to grow, so it renders the four the design already
  // names. The other three are on the endpoint for anyone who asks.
  const items = useMemo(() => {
    const byName = new Map((pipeline?.nodes || []).map((n) => [n.name, n]));
    return PIPELINE_NODES.map((name) => {
      const node = byName.get(name);
      return { name, state: node?.state ?? "--", load: node?.load ?? 0 };
    });
  }, [pipeline]);

  return (
    <div className="panel">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <span className="mono-label flex items-center gap-2">
          <Cpu className="h-3 w-3 text-primary" /> pipeline activity
        </span>
        <ArrowUpRight className="h-3 w-3 text-muted-foreground" />
      </div>
      <div className="space-y-3 px-4 py-3">
        {items.map((a, i) => (
          <div key={a.name}>
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span className="uppercase tracking-[0.12em]">{a.name}</span>
              <span className={a.state === "active" ? "text-signal" : "text-primary"}>{a.state}</span>
            </div>
            <div className="mt-1.5 h-1.5 w-full bg-muted">
              <motion.div
                className={`h-full ${a.state === "active" ? "bg-signal" : "bg-primary"}`}
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

export function RightRail() {
  const rail = useRailMetrics();
  return (
    <div className="space-y-4">
      <SignalVelocity velocity={rail?.signal_velocity} forecast={rail?.threat_forecast} />
      <AttackSurface surface={rail?.attack_surface} />
      <AgentActivity pipeline={rail?.pipeline_activity} />
    </div>
  );
}
