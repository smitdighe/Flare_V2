import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Activity, Zap, Layers, ShieldCheck, Terminal, ArrowUpRight, CheckCircle2 } from 'lucide-react';
import { Reveal } from './Primitives.jsx';

const STREAM_EVENTS = [
  { time: '17:42:01.214', type: 'INGEST', host: '205.174.165.73', detail: 'SURICATA_ALERT // Inbound TCP 80' },
  { time: '17:42:01.442', type: 'ENRICH', host: 'AbuseIPDB', detail: 'Reputation 100% (1,482 reports)' },
  { time: '17:42:01.710', type: 'VERDICT', host: 'Rule #418', detail: 'ATT&CK T1071.001 -> Block Directive Issued' },
  { time: '17:42:02.051', type: 'INGEST', host: '185.220.101.5', detail: 'SSH_AUTH_FAIL // Tor Exit Node' },
  { time: '17:42:02.289', type: 'ENRICH', host: 'VirusTotal', detail: '18/87 Security Vendors Malicious' },
];

export function CapabilitiesBento() {
  const [eventIndex, setEventIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setEventIndex((prev) => (prev + 1) % STREAM_EVENTS.length);
    }, 2400);
    return () => clearInterval(timer);
  }, []);

  const visibleEvents = [
    STREAM_EVENTS[eventIndex],
    STREAM_EVENTS[(eventIndex + 1) % STREAM_EVENTS.length],
    STREAM_EVENTS[(eventIndex + 2) % STREAM_EVENTS.length],
  ];

  return (
    <section id="capabilities" className="relative z-20 mx-auto max-w-[1400px] px-6 pb-28 md:px-12">
      <Reveal>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-white font-semibold">
            what it gives you
          </span>
        </div>
        <h2 className="font-display mt-3 text-2xl md:text-3xl lg:text-4xl font-bold tracking-tight text-white">
          Architected for immediate clarity.
        </h2>
      </Reveal>

      {/* Asymmetric High-Tech Bento Grid */}
      <div className="mt-8 grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Tile 1: Live Feed (7 Cols) */}
        <Reveal delay={100} variant="scale" className="lg:col-span-7">
          <div className="group relative h-full flex flex-col justify-between overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent p-6 lg:p-8 backdrop-blur-2xl transition-all duration-300 hover:border-white/30 shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
            {/* Top Accent Gradient */}
            <div className="pointer-events-none absolute -top-24 -left-24 h-56 w-56 rounded-full bg-white/10 blur-3xl transition-opacity duration-500 group-hover:opacity-100 opacity-50" />

            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-white">
                  <Activity className="h-3 w-3 animate-pulse text-white" />
                  <span>live feed</span>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px] text-zinc-500">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-ping" />
                  <span className="text-emerald-400 font-medium">WS // 1.4ms ping</span>
                </div>
              </div>

              <h3 className="font-display mt-5 text-2xl font-bold tracking-tight text-white">
                Streaming, not polling.
              </h3>
              <p className="mt-2.5 text-sm leading-relaxed text-zinc-400 font-sans max-w-lg">
                WebSocket + SSE push every verdict to the console the moment the pipeline settles.
              </p>
            </div>

            {/* Live Socket Feed Visualizer Widget */}
            <div className="mt-6 rounded-xl border border-white/[0.06] bg-[#08090d] p-4 font-mono shadow-inner">
              <div className="flex items-center justify-between border-b border-white/[0.06] pb-2 text-[10px] text-zinc-500">
                <div className="flex items-center gap-1.5">
                  <Terminal className="h-3 w-3 text-zinc-300" />
                  <span className="text-zinc-400">wss://api.flare.internal/v2/stream</span>
                </div>
                <span className="text-zinc-300 font-medium">DUPLEX ACTIVE</span>
              </div>

              {/* Rolling Live Stream Lines */}
              <div className="mt-3 space-y-2 text-[11px]">
                {visibleEvents.map((ev, i) => (
                  <motion.div
                    key={`${ev.time}-${ev.host}`}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.2 }}
                    className={`flex flex-col sm:flex-row sm:items-center justify-between gap-1 rounded-lg px-2.5 py-1.5 transition-colors ${
                      i === 0
                        ? 'border border-white/20 bg-white/10 text-white'
                        : 'text-zinc-400 bg-white/[0.01]'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-zinc-500 text-[10px]">{ev.time}</span>
                      <span className="rounded bg-white/10 px-1.5 py-0.2 text-[9px] font-semibold text-zinc-300">
                        {ev.type}
                      </span>
                      <span className="font-medium text-zinc-200">{ev.host}</span>
                    </div>
                    <span className="text-zinc-400 text-[10px] truncate">{ev.detail}</span>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </Reveal>

        {/* Tile 2: Sub-Second Latency (5 Cols) */}
        <Reveal delay={200} variant="scale" className="lg:col-span-5">
          <div className="group relative h-full flex flex-col justify-between overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent p-6 lg:p-8 backdrop-blur-2xl transition-all duration-300 hover:border-white/30 shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
            {/* Top Accent Gradient */}
            <div className="pointer-events-none absolute -top-24 -right-24 h-56 w-56 rounded-full bg-amber-500/10 blur-3xl transition-opacity duration-500 group-hover:opacity-100 opacity-50" />

            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-white">
                  <Zap className="h-3 w-3 text-white" />
                  <span>sub-second</span>
                </div>
                <span className="rounded border border-white/30 bg-white/10 px-2 py-0.5 font-mono text-[9px] font-semibold text-white">
                  98.6% FASTER
                </span>
              </div>

              <h3 className="font-display mt-5 text-2xl font-bold tracking-tight text-white">
                Triage before the noise compounds.
              </h3>
              <p className="mt-2.5 text-sm leading-relaxed text-zinc-400 font-sans">
                Classification and context land in the same breath, so the queue never gets ahead of you.
              </p>
            </div>

            {/* Benchmark Latency Comparison Meter */}
            <div className="mt-6 rounded-xl border border-white/[0.06] bg-[#08090d] p-4 font-mono shadow-inner">
              <div className="space-y-3.5 text-xs">
                <div>
                  <div className="flex justify-between text-[10px] text-zinc-400 mb-1">
                    <span className="font-medium text-zinc-300">Legacy SOC / Manual Queue</span>
                    <span className="text-zinc-500">~42m 18s</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-white/[0.05] overflow-hidden">
                    <div className="h-full w-[94%] rounded-full bg-zinc-700" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-[10px] text-white mb-1 font-semibold">
                    <span>Flare Agentic Triage</span>
                    <span className="text-white">&lt; 1s (910ms total)</span>
                  </div>
                  <div className="h-2.5 w-full rounded-full bg-white/[0.05] overflow-hidden p-0.5">
                    <div className="h-full w-[24%] rounded-full bg-gradient-to-r from-zinc-300 to-white shadow-[0_0_12px_rgba(255,255,255,0.4)]" />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-1.5 pt-2 border-t border-white/[0.06] text-center text-[9px]">
                  <div className="rounded border border-white/[0.04] bg-white/[0.02] p-1.5">
                    <span className="text-zinc-500 block">CLASSIFY</span>
                    <span className="text-zinc-200 font-semibold">~240ms</span>
                  </div>
                  <div className="rounded border border-white/[0.04] bg-white/[0.02] p-1.5">
                    <span className="text-zinc-500 block">ENRICH</span>
                    <span className="text-zinc-200 font-semibold">~380ms</span>
                  </div>
                  <div className="rounded border border-white/[0.04] bg-white/[0.02] p-1.5">
                    <span className="text-zinc-500 block">REASON</span>
                    <span className="text-zinc-200 font-semibold">~290ms</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Reveal>

        {/* Tile 3: Grounded Evidence Dossier (12 Cols Full Width) */}
        <Reveal delay={300} variant="scale" className="lg:col-span-12">
          <div className="group relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent p-6 lg:p-8 backdrop-blur-2xl transition-all duration-300 hover:border-white/30 shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
            {/* Ambient Background Glow */}
            <div className="pointer-events-none absolute bottom-0 right-1/4 h-64 w-96 rounded-full bg-white/5 blur-3xl transition-opacity duration-500 group-hover:opacity-100 opacity-40" />

            <div className="grid gap-8 lg:grid-cols-12 items-center">
              {/* Left Details */}
              <div className="lg:col-span-5">
                <div className="flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-white w-fit">
                  <Layers className="h-3 w-3 text-white" />
                  <span>grounded</span>
                </div>

                <h3 className="font-display mt-4 text-2xl lg:text-3xl font-bold tracking-tight text-white">
                  Evidence attached to every call.
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-zinc-400 font-sans">
                  Each verdict carries the reputation data and the ATT&CK technique it was reasoned from.
                </p>

                <div className="mt-6 flex flex-wrap gap-2 text-xs font-mono text-zinc-300">
                  <div className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 text-white" />
                    <span>Deterministic telemetry</span>
                  </div>
                  <div className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-1.5">
                    <ShieldCheck className="h-3.5 w-3.5 text-white" />
                    <span>MITRE Enterprise aligned</span>
                  </div>
                </div>
              </div>

              {/* Right Interactive Attested Dossier */}
              <div className="lg:col-span-7 rounded-xl border border-white/[0.08] bg-[#08090d] p-5 shadow-2xl">
                <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 font-mono text-xs">
                  <div className="flex items-center gap-2 text-white font-semibold">
                    <ShieldCheck className="h-4 w-4 text-white" />
                    <span>INCIDENT DOSSIER #FLR-8921</span>
                  </div>
                  <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                    VERIFIED ATTESTATION
                  </span>
                </div>

                {/* Grounding Data Matrix */}
                <div className="mt-4 grid gap-2.5 sm:grid-cols-3 font-mono">
                  <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                    <div className="text-[9px] uppercase tracking-wider text-zinc-500">MITRE ATT&CK</div>
                    <div className="mt-1 font-sans text-xs font-bold text-white">T1071.001</div>
                    <div className="text-[10px] text-zinc-400 truncate mt-0.5">Web Protocols</div>
                  </div>

                  <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                    <div className="text-[9px] uppercase tracking-wider text-zinc-500">AbuseIPDB</div>
                    <div className="mt-1 font-sans text-xs font-bold text-amber-400">100% Score</div>
                    <div className="text-[10px] text-zinc-400 truncate mt-0.5">1,482 Reports</div>
                  </div>

                  <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                    <div className="text-[9px] uppercase tracking-wider text-zinc-500">VirusTotal</div>
                    <div className="mt-1 font-sans text-xs font-bold text-red-400">18 / 87 Engines</div>
                    <div className="text-[10px] text-zinc-400 truncate mt-0.5">Flagged Malicious</div>
                  </div>
                </div>

                {/* Direct Action Plan */}
                <div className="mt-3 flex items-center justify-between rounded-lg border border-white/20 bg-white/[0.04] p-3 font-mono text-xs">
                  <div className="flex items-center gap-2 text-zinc-300">
                    <span className="text-white font-bold">›</span>
                    <span>Direct Action: <span className="text-white font-semibold">Firewall Rule #418</span> generated</span>
                  </div>
                  <span className="text-[10px] text-white uppercase font-semibold">Ready to deploy</span>
                </div>
              </div>

            </div>
          </div>
        </Reveal>

      </div>
    </section>
  );
}
