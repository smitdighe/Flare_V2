import { useState } from 'react';
import { Reveal } from './Primitives.jsx';

const STAGES = [
  {
    n: '01', accent: 'oklch(0.82 0.16 78)', pattern: 'mesh',
    title: 'Separate signal from noise.',
    body: 'Every event is scored against severity and attack vector before it reaches an analyst.',
    tag: 'classify // agent stage',
    detail: [
      { label: 'model', value: 'Groq \u00b7 Llama 3.1' },
      { label: 'output', value: 'severity + attack type' },
      { label: 'latency', value: '~240ms' },
    ],
    steps: [
      'normalise the raw IDS record',
      'score severity across 4 bands',
      'label the attack vector',
      'drop benign traffic before enrichment',
    ],
  },
  {
    n: '02', accent: 'oklch(0.76 0.175 55)', pattern: 'arcs',
    title: 'Add the missing context.',
    body: 'AbuseIPDB and VirusTotal turn a raw source IP into evidence you can act on.',
    tag: 'enrich // agent stage',
    detail: [
      { label: 'sources', value: 'AbuseIPDB \u00b7 VirusTotal' },
      { label: 'output', value: 'IOC reputation + verdict' },
      { label: 'cache', value: 'per-IP, TTL bounded' },
    ],
    steps: [
      'resolve source IP reputation',
      'pull vendor detection ratios',
      'attach geo + ASN ownership',
      'flag repeat offenders across the feed',
    ],
  },
  {
    n: '03', accent: 'oklch(0.68 0.19 38)', pattern: 'reticle',
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
  },
];

function Pattern({ kind, accent }) {
  const common = 'pointer-events-none absolute inset-0 opacity-25 transition-opacity duration-700 group-hover:opacity-60';
  if (kind === 'mesh') {
    return (
      <svg className={common} aria-hidden>
        <defs>
          <pattern id="p-mesh" width="34" height="30" patternUnits="userSpaceOnUse">
            <path d="M0 30 L17 0 L34 30 Z" fill="none" stroke={accent} strokeWidth="0.5" />
            <path d="M-17 0 L0 30 L17 0" fill="none" stroke={accent} strokeWidth="0.5" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#p-mesh)" />
      </svg>
    );
  }
  if (kind === 'arcs') {
    return (
      <svg className={common} aria-hidden>
        <g fill="none" stroke={accent} strokeWidth="0.6">
          {[40, 80, 120, 160, 200, 240, 280].map((r) => (
            <circle key={r} cx="8%" cy="105%" r={r} className="animate-pulse" style={{ animationDuration: `${3 + r / 60}s` }} />
          ))}
        </g>
      </svg>
    );
  }
  return (
    <svg className={common} aria-hidden>
      <defs>
        <pattern id="p-ret" width="26" height="26" patternUnits="userSpaceOnUse">
          <path d="M13 9 V17 M9 13 H17" stroke={accent} strokeWidth="0.6" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#p-ret)" />
      <circle cx="50%" cy="50%" r="70" fill="none" stroke={accent} strokeWidth="0.6" strokeDasharray="4 8" className="animate-spin-slow" style={{ transformOrigin: 'center' }} />
    </svg>
  );
}

export function StageCards() {
  const [open, setOpen] = useState('01');

  return (
    <div className="mt-20 grid border-y border-border md:grid-cols-3 md:divide-x md:divide-border">
      {STAGES.map((s, i) => {
        const isOpen = open === s.n;
        return (
          <Reveal key={s.n} delay={i * 200} variant="scale">
            <button
              type="button"
              onClick={() => setOpen(isOpen ? null : s.n)}
              aria-expanded={isOpen}
              className="tilt-card group relative block h-full w-full overflow-hidden p-8 text-left"
              style={{
                background: isOpen
                  ? `radial-gradient(ellipse 120% 90% at 50% 0%, color-mix(in oklab, ${s.accent} 12%, transparent), transparent 70%)`
                  : undefined,
              }}
            >
              <Pattern kind={s.pattern} accent={s.accent} />
              <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px origin-left scale-x-0 transition-transform duration-700 group-hover:scale-x-100" style={{ background: s.accent }} />

              <span className="relative flex items-start justify-between">
                <span className="label">{s.n}</span>
                <span className="icon" style={{ color: s.accent }}>&#9670;</span>
              </span>

              <span className="relative mt-8 block h-0.5 w-10 transition-all duration-500 group-hover:w-24" style={{ background: s.accent, boxShadow: `0 0 18px ${s.accent}` }} />

              <span className="display relative mt-6 block text-xl italic">{s.title}</span>
              <span className="relative mt-4 block text-sm leading-relaxed text-muted-foreground">{s.body}</span>

              <span className="relative block overflow-hidden transition-all duration-700" style={{ maxHeight: isOpen ? 420 : 0, opacity: isOpen ? 1 : 0 }}>
                <span className="mt-7 block space-y-px border border-border">
                  {s.detail.map((d) => (
                    <span key={d.label} className="flex items-center justify-between bg-card/70 px-3 py-2">
                      <span className="label">{d.label}</span>
                      <span className="font-mono text-[11px] text-foreground/80">{d.value}</span>
                    </span>
                  ))}
                </span>
                <span className="mt-5 block space-y-2 border-l pl-4" style={{ borderColor: s.accent }}>
                  {s.steps.map((step, k) => (
                    <span key={step} className="block font-mono text-[11px] text-muted-foreground transition-all" style={{ transitionDelay: `${isOpen ? 140 + k * 90 : 0}ms`, transform: isOpen ? 'none' : 'translateX(-10px)', opacity: isOpen ? 1 : 0 }}>
                      <span style={{ color: s.accent }}>&gt;</span> {step}
                    </span>
                  ))}
                </span>
              </span>

              <span className="relative mt-10 flex items-center justify-between">
                <span className="label">{s.tag}</span>
                <span className="flex items-center gap-2">
                  <span className="label" style={{ color: s.accent }}>{isOpen ? 'collapse' : 'expand'}</span>
                  <span className="icon text-sm transition-transform duration-500" style={{ color: s.accent, transform: isOpen ? 'rotate(135deg)' : 'none' }}>+</span>
                </span>
              </span>
            </button>
          </Reveal>
        );
      })}
    </div>
  );
}
