import { useEffect, useState } from 'react';
import { motion } from 'motion/react';

const EVENTS = [
  ['10.4.19.7', 'portscan', 'medium'],
  ['45.155.205.233', 'brute force', 'high'],
  ['192.168.3.44', 'dns tunnel', 'low'],
  ['185.220.101.9', 'c2 beacon', 'critical'],
  ['172.16.8.21', 'web shell', 'high'],
  ['103.97.3.18', 'credential stuffing', 'medium'],
];

const sevColor = {
  low: 'text-muted-foreground',
  medium: 'text-accent',
  high: 'text-accent',
  critical: 'text-destructive',
};

export function TelemetryPanel() {
  const [cursor, setCursor] = useState(0);
  const [latency, setLatency] = useState(0.61);

  useEffect(() => {
    const t = setInterval(() => {
      setCursor((c) => (c + 1) % EVENTS.length);
      setLatency(0.42 + Math.random() * 0.45);
    }, 2200);
    return () => clearInterval(t);
  }, []);

  const feed = Array.from(
    { length: 4 },
    (_, i) => EVENTS[(cursor + i) % EVENTS.length],
  );

  return (
    <div className="panel scanline relative">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <span className="mono-label">field telemetry</span>
        <span className="mono-label flex items-center gap-2 text-signal-ok">
          <span className="animate-blink h-1.5 w-1.5 rounded-full bg-signal-ok" /> live
        </span>
      </div>

      <div className="grid grid-cols-2 divide-x divide-border border-b border-border">
        <div className="px-4 py-3">
          <div className="mono-label">accuracy metric</div>
          <div className="font-display mt-1 text-3xl text-accent">0.613</div>
          <div className="mono-label mt-1 normal-case tracking-normal">F1 // CICIDS2017</div>
        </div>
        <div className="px-4 py-3">
          <div className="mono-label">triage latency</div>
          <motion.div
            key={latency}
            initial={{ opacity: 0.3, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="font-display mt-1 text-3xl"
          >
            {latency.toFixed(2)}s
          </motion.div>
          <div className="mono-label mt-1 normal-case tracking-normal">classifier + context</div>
        </div>
      </div>

      <div className="px-4 py-3">
        <div className="mono-label mb-2">inbound queue</div>
        <div className="space-y-1.5">
          {feed.map((e, i) => (
            <motion.div
              key={`${e[0]}-${cursor}-${i}`}
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1 - i * 0.22, x: 0 }}
              transition={{ delay: i * 0.05 }}
              className="flex items-center justify-between gap-3 font-mono text-[11px]"
            >
              <span className="text-foreground">{e[0]}</span>
              <span className="flex-1 truncate text-muted-foreground">{e[1]}</span>
              <span className={sevColor[e[2]]}>{e[2]}</span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}

const TAGS = [
  'mitre att&ck grounded',
  'websocket live feed',
  'abuseipdb',
  'virustotal',
  'langgraph pipeline',
  'classify',
  'enrich',
  'reason',
  'rbac enforced',
];

export function Marquee() {
  return (
    <div className="relative overflow-hidden border-y border-border py-2.5">
      <div className="animate-marquee flex w-max gap-8">
        {[...TAGS, ...TAGS].map((t, i) => (
          <span key={i} className="mono-label whitespace-nowrap">
            {t} <span className="text-accent">/</span>
          </span>
        ))}
      </div>
    </div>
  );
}
