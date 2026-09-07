import { useEffect, useState } from 'react';

const VECTORS = [
  ['SQL_INJECTION', 'T1190'], ['BRUTE_FORCE', 'T1110'], ['PORT_SCAN', 'T1046'],
  ['DNS_TUNNEL', 'T1071'], ['CRED_DUMP', 'T1003'], ['LATERAL_SMB', 'T1021'],
];

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM'];

function pad(n) { return n.toString().padStart(2, '0'); }

function makeRow(seed) {
  const v = VECTORS[seed % VECTORS.length];
  const sev = SEVERITIES[seed % SEVERITIES.length];
  return {
    time: `${pad(14 + ((seed * 7) % 6))}:${pad((seed * 13) % 60)}:${pad((seed * 29) % 60)}`,
    severity: sev, vector: v[0],
    source: `${45 + ((seed * 11) % 180)}.${(seed * 17) % 250}.${(seed * 23) % 250}.${(seed * 31) % 250}`,
    mitre: v[1],
  };
}

const sevColor = {
  CRITICAL: 'text-signal-critical',
  HIGH: 'text-signal-high',
  MEDIUM: 'text-signal-medium',
};

export function TriageBuffer() {
  const [rows, setRows] = useState(() => [makeRow(3), makeRow(8), makeRow(14), makeRow(21)]);
  const [count, setCount] = useState(112);

  useEffect(() => {
    let seed = 30;
    const id = setInterval(() => {
      seed += 5;
      setRows((prev) => [makeRow(seed), ...prev].slice(0, 4));
      setCount((c) => c + 1);
    }, 2600);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="panel relative overflow-hidden rounded-md">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-16 animate-scan opacity-60" style={{ background: 'linear-gradient(to bottom, transparent, color-mix(in oklab, var(--accent) 12%, transparent), transparent)' }} />
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <span className="label flex items-center gap-2">
          <span className="animate-blink inline-block h-1.5 w-1.5 rounded-full bg-signal-ok" />
          live triage buffer
        </span>
        <span className="label">{count} of 200 signals</span>
      </div>

      <div className="grid grid-cols-[76px_1fr_1fr_1fr_60px] gap-3 border-b border-border/60 px-5 py-2.5">
        {['time', 'severity', 'vector', 'source', 'mitre'].map((h) => (
          <span key={h} className="label">{h}</span>
        ))}
      </div>

      <div className="divide-y divide-border/40">
        {rows.map((r, i) => (
          <div key={`${r.time}-${r.vector}-${i}`} className="grid animate-[fade-in_0.5s_var(--ease-out-soft)] grid-cols-[76px_1fr_1fr_1fr_60px] items-center gap-3 px-5 py-3 font-mono text-[11px] transition-colors hover:bg-secondary/50" style={{ opacity: 1 - i * 0.16 }}>
            <span className="text-foreground">{r.time}</span>
            <span className={sevColor[r.severity]}>[ {r.severity} ]</span>
            <span className="text-foreground/80">{r.vector}</span>
            <span className="text-muted-foreground">{r.source}</span>
            <span className="text-accent">{r.mitre}</span>
          </div>
        ))}
      </div>

      <a href="/login" className="group flex items-center justify-between border-t border-border px-5 py-3.5 transition-colors hover:bg-secondary/40">
        <span className="label text-foreground/70">inspect the full buffer</span>
        <span className="text-accent transition-transform group-hover:translate-x-1">&rarr;</span>
      </a>
    </div>
  );
}
