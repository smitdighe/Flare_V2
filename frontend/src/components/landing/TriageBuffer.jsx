import { useEffect, useState } from 'react';
import { ArrowRight } from 'lucide-react';

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

const sevBadge = {
  CRITICAL: 'text-destructive border-destructive/40 bg-destructive/10',
  HIGH: 'text-primary border-primary/40 bg-primary/10',
  MEDIUM: 'text-yellow-400 border-yellow-400/40 bg-yellow-400/10',
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
    <div className="relative overflow-hidden rounded-xl border border-border/60 bg-card/70 backdrop-blur-xl">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-border/40 px-5 py-3.5 bg-secondary/15">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-border" />
            <span className="h-2.5 w-2.5 rounded-full bg-border" />
            <span className="h-2.5 w-2.5 rounded-full bg-border" />
          </div>
          <span className="font-mono text-xs uppercase tracking-wider text-foreground font-semibold flex items-center gap-2">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-signal animate-blink" />
            live triage buffer
          </span>
        </div>
        <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">{count} of 200 signals</span>
      </div>

      <div className="grid grid-cols-[76px_1fr_1.1fr_1.1fr_60px] gap-3 border-b border-border/40 px-5 py-2.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground/80">
        {['time', 'severity', 'vector', 'source', 'mitre'].map((h) => (
          <span key={h}>{h}</span>
        ))}
      </div>

      <div className="divide-y divide-border/30">
        {rows.map((r, i) => (
          <div key={`${r.time}-${r.vector}-${i}`} className="grid grid-cols-[76px_1fr_1.1fr_1.1fr_60px] items-center gap-3 px-5 py-3 font-mono text-[11px] transition-colors hover:bg-secondary/40" style={{ opacity: 1 - i * 0.15 }}>
            <span className="text-foreground/90 font-medium">{r.time}</span>
            <div>
              <span className={`inline-block rounded border px-1.5 py-0.5 text-[9px] font-semibold tracking-wider ${sevBadge[r.severity]}`}>
                {r.severity}
              </span>
            </div>
            <span className="text-foreground/80 truncate">{r.vector}</span>
            <span className="text-muted-foreground truncate">{r.source}</span>
            <span className="text-primary font-medium">{r.mitre}</span>
          </div>
        ))}
      </div>

      <a href="/login" className="group flex items-center justify-between border-t border-border/40 px-5 py-3.5 transition-colors hover:bg-secondary/30">
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground transition-colors group-hover:text-foreground">
          inspect the full buffer
        </span>
        <ArrowRight className="h-3.5 w-3.5 text-primary transition-transform group-hover:translate-x-1" />
      </a>
    </div>
  );
}
