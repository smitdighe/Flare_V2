import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Filter, Database, BrainCircuit, CheckCircle2, Terminal, ArrowRight, Activity, ShieldCheck, ChevronRight } from 'lucide-react';

const STAGES = [
  {
    n: '01',
    name: 'Classify',
    icon: Filter,
    accent: '#f59e0b',
    title: 'Separate signal from noise.',
    body: 'Every event is scored against severity and attack vector before it reaches an analyst.',
    tag: 'classify // agent stage',
    detail: [
      { label: 'model', value: 'Groq · Llama 3.1' },
      { label: 'output', value: 'severity + attack type' },
      { label: 'latency', value: '~240ms' },
    ],
    steps: [
      'normalise the raw IDS record',
      'score severity across 4 bands',
      'label the attack vector',
      'drop benign traffic before enrichment',
    ],
    mockArtifact: {
      type: 'Triage Vector',
      badge: 'HIGH CONFIDENCE',
      fields: [
        { key: 'Input Record', val: 'SURICATA IDS // 205.174.165.73:80' },
        { key: 'Classification', val: 'Botnet // C2 Communication' },
        { key: 'Severity Band', val: 'High (0.84 score)' },
        { key: 'Filter Action', val: 'Pass to Enrichment stage' },
      ],
    },
  },
  {
    n: '02',
    name: 'Enrich',
    icon: Database,
    accent: '#fb923c',
    title: 'Add the missing context.',
    body: 'AbuseIPDB and VirusTotal turn a raw source IP into evidence you can act on.',
    tag: 'enrich // agent stage',
    detail: [
      { label: 'sources', value: 'AbuseIPDB · VirusTotal' },
      { label: 'output', value: 'IOC reputation + verdict' },
      { label: 'cache', value: 'per-IP, TTL bounded' },
    ],
    steps: [
      'resolve source IP reputation',
      'pull vendor detection ratios',
      'attach geo + ASN ownership',
      'flag repeat offenders across the feed',
    ],
    mockArtifact: {
      type: 'Threat Intel Report',
      badge: 'VERIFIED REPUTATION',
      fields: [
        { key: 'AbuseIPDB Score', val: '100% (1,482 reports)' },
        { key: 'VirusTotal Ratio', val: '18 / 87 security vendors' },
        { key: 'ASN / Geo', val: 'AS16276 · Roubaix, France' },
        { key: 'Feed Correlation', val: 'Repeat offender in cluster #4' },
      ],
    },
  },
  {
    n: '03',
    name: 'Reason',
    icon: BrainCircuit,
    accent: '#ea580c',
    title: 'Make the next move legible.',
    body: 'MITRE-grounded reasoning turns a verdict into a bounded remediation path.',
    tag: 'reason // agent stage',
    detail: [
      { label: 'model', value: 'Gemini + MITRE RAG' },
      { label: 'output', value: 'technique + remediation' },
      { label: 'grounding', value: 'ATT&CK enterprise' },
    ],
    steps: [
      'retrieve matching ATT&CK techniques',
      'explain the chain in analyst language',
      'propose bounded remediation steps',
      'hand off a decision, not a guess',
    ],
    mockArtifact: {
      type: 'Remediation Directive',
      badge: 'MITRE ATT&CK GROUNDED',
      fields: [
        { key: 'Technique ID', val: 'T1071.001 (Web Protocols)' },
        { key: 'Analyst Summary', val: 'Inbound beaconing to active C2 host' },
        { key: 'Action Plan', val: 'Block IP on border firewall (Rule #418)' },
        { key: 'Handoff Status', val: 'Ready for 1-click execution' },
      ],
    },
  },
];

export function StageCards() {
  const [activeStage, setActiveStage] = useState(0);
  const current = STAGES[activeStage];

  return (
    <div className="space-y-6">
      {/* Interactive Pipeline Ribbon & Continuous Connector Rail */}
      <div className="relative rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent p-2 backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {STAGES.map((s, idx) => {
            const isSelected = activeStage === idx;
            const Icon = s.icon;
            return (
              <button
                key={s.n}
                type="button"
                onClick={() => setActiveStage(idx)}
                className={`group relative flex items-center justify-between rounded-xl px-5 py-4 text-left transition-all duration-300 ${
                  isSelected
                    ? 'text-white'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03]'
                }`}
              >
                {/* Active Indicator Glow Background */}
                {isSelected && (
                  <motion.div
                    layoutId="active-stage-glow"
                    transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                    className="absolute inset-0 rounded-xl border border-white/20 bg-gradient-to-r from-white/10 via-white/5 to-transparent shadow-[0_0_24px_rgba(255,255,255,0.15)]"
                  />
                )}

                <div className="relative flex items-center gap-3.5 min-w-0">
                  <div
                    className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border transition-all duration-300 ${
                      isSelected
                        ? 'border-white/40 bg-white/10 text-white shadow-[0_0_16px_rgba(255,255,255,0.2)]'
                        : 'border-white/10 bg-white/[0.02] text-zinc-500 group-hover:border-white/20 group-hover:text-zinc-300'
                    }`}
                  >
                    <Icon className="h-4.5 w-4.5" />
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] font-bold text-white">{s.n}</span>
                      <span className="text-white/20 font-mono text-xs">//</span>
                      <span className="font-sans text-xs font-bold uppercase tracking-wider text-white">
                        {s.name}
                      </span>
                    </div>
                    <div className="font-sans text-xs text-zinc-400 truncate mt-0.5 max-w-[200px]">
                      {s.title}
                    </div>
                  </div>
                </div>

                {/* Right Flow Arrow / Status Pill */}
                <div className="relative flex items-center pl-2">
                  {isSelected ? (
                    <span className="flex items-center gap-1.5 rounded-full border border-white/30 bg-white/10 px-2 py-0.5 font-mono text-[9px] font-semibold text-white uppercase">
                      <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
                      Active
                    </span>
                  ) : (
                    <ChevronRight className="h-4 w-4 text-zinc-600 transition-transform group-hover:translate-x-0.5 group-hover:text-zinc-400" />
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Live Pipeline Execution Stage Inspector */}
      <AnimatePresence mode="wait">
        <motion.div
          key={current.n}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.25 }}
          className="rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_24px_60px_-12px_rgba(0,0,0,0.85)] p-6 lg:p-8 overflow-hidden"
        >
          <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr] items-start">
            {/* Left Column: Stage Overview & Steps */}
            <div>
              <div className="flex items-center gap-2.5">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-white/30 bg-white/10 px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-white font-semibold">
                  <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
                  {current.tag}
                </span>
                <span className="font-mono text-xs text-zinc-500">STAGE {current.n} OF 03</span>
              </div>

              <h3 className="font-sans mt-4 text-2xl lg:text-3xl font-bold tracking-tight text-white">
                {current.title}
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-zinc-400 font-sans max-w-xl">
                {current.body}
              </p>

              {/* Execution Steps Checklist */}
              <div className="mt-6 space-y-2.5 border-t border-white/[0.06] pt-6">
                <div className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 font-semibold">
                  Execution sequence
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {current.steps.map((step) => (
                    <div
                      key={step}
                      className="flex items-center gap-2.5 rounded-xl border border-white/[0.04] bg-white/[0.02] p-3 text-xs text-zinc-300 transition-colors hover:border-white/10 hover:bg-white/[0.04]"
                    >
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-white" />
                      <span className="font-sans capitalize">{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Column: Interactive Stage Payload & Telemetry Widget */}
            <div className="rounded-xl border border-white/[0.08] bg-[#10131b]/90 p-5 shadow-xl">
              <div className="flex items-center justify-between border-b border-white/[0.08] pb-3">
                <div className="flex items-center gap-2 font-mono text-[11px] font-semibold text-white">
                  <Terminal className="h-3.5 w-3.5 text-white" />
                  <span>{current.mockArtifact.type}</span>
                </div>
                <span className="rounded-md border border-white/30 bg-white/10 px-2 py-0.5 font-mono text-[9px] font-semibold text-white">
                  {current.mockArtifact.badge}
                </span>
              </div>

              {/* Payload Field Inspector */}
              <div className="mt-4 space-y-2.5 font-mono text-xs">
                {current.mockArtifact.fields.map((f) => (
                  <div key={f.key} className="rounded-lg border border-white/[0.04] bg-white/[0.02] px-3 py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <span className="text-[10px] uppercase tracking-wider text-zinc-500">{f.key}</span>
                    <span className="text-zinc-200 font-medium text-right truncate">{f.val}</span>
                  </div>
                ))}
              </div>

              {/* Stage Infrastructure Metrics */}
              <div className="mt-5 grid grid-cols-3 gap-2 border-t border-white/[0.06] pt-4 text-center">
                {current.detail.map((d) => (
                  <div key={d.label} className="rounded-lg border border-white/[0.04] bg-white/[0.02] p-2">
                    <div className="font-mono text-[9px] uppercase tracking-wider text-zinc-500">{d.label}</div>
                    <div className="font-sans text-xs font-semibold text-white mt-0.5 truncate">{d.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
