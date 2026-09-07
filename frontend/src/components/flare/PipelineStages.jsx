import { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Filter, Crosshair, Radar, Plus, X } from 'lucide-react';

const STAGES = [
  {
    id: 'classify',
    index: '01',
    name: 'classify',
    title: 'Separate signal from noise.',
    blurb: 'Every event is scored against severity and attack vector before it reaches an analyst.',
    icon: Filter,
    meta: [
      ['model', 'Groq \u00b7 Llama 3.1'],
      ['output', 'severity + attack type'],
      ['latency', '~240ms'],
    ],
    steps: [
      'normalise the raw IDS record',
      'score severity across 4 bands',
      'label the attack vector',
      'drop benign traffic before enrichment',
    ],
  },
  {
    id: 'enrich',
    index: '02',
    name: 'enrich',
    title: 'Add the missing context.',
    blurb: 'AbuseIPDB and VirusTotal turn a raw source IP into evidence you can act on.',
    icon: Crosshair,
    meta: [
      ['sources', 'AbuseIPDB \u00b7 VirusTotal'],
      ['output', 'IOC reputation + verdict'],
      ['cache', '24h per indicator'],
    ],
    steps: [
      'resolve source IP reputation',
      'pull file + domain verdicts',
      'attach confidence to each indicator',
      'flag known infrastructure reuse',
    ],
  },
  {
    id: 'reason',
    index: '03',
    name: 'reason',
    title: 'Make the next move legible.',
    blurb: 'MITRE-grounded reasoning turns a verdict into a bounded remediation path.',
    icon: Radar,
    meta: [
      ['model', 'Gemini + RAG'],
      ['grounding', 'MITRE ATT&CK'],
      ['output', 'technique + remediation'],
    ],
    steps: [
      'retrieve matching ATT&CK techniques',
      'explain the verdict in one paragraph',
      'emit ordered remediation steps',
      'hand off to a playbook',
    ],
  },
];

export function PipelineStages() {
  const [open, setOpen] = useState('classify');

  return (
    <div className="border-t border-border">
      {STAGES.map((stage) => {
        const isOpen = open === stage.id;
        const StageIcon = stage.icon;
        return (
          <div key={stage.id} className="border-b border-border">
            <button
              type="button"
              onClick={() => setOpen(isOpen ? null : stage.id)}
              className="group flex w-full items-center gap-4 py-4 text-left transition-colors hover:bg-accent/30"
              aria-expanded={isOpen}
            >
              <span className="mono-label w-8 shrink-0">{stage.index}</span>
              <StageIcon
                className={`h-4 w-4 shrink-0 transition-colors ${isOpen ? 'text-accent' : 'text-muted-foreground group-hover:text-accent'}`}
              />
              <span className="font-display flex-1 text-xl leading-none tracking-tight">
                {stage.title}
              </span>
              <span className="mono-label hidden shrink-0 items-center gap-2 text-accent sm:flex">
                {isOpen ? 'collapse' : 'expand'}
                {isOpen ? <X className="h-3 w-3" /> : <Plus className="h-3 w-3" />}
              </span>
            </button>

            <AnimatePresence initial={false}>
              {isOpen && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
                  className="overflow-hidden"
                >
                  <div className="pb-6 pl-12 pr-2">
                    <p className="max-w-md text-sm leading-relaxed text-muted-foreground">
                      {stage.blurb}
                    </p>

                    <dl className="mt-4 max-w-md divide-y divide-border border border-border">
                      {stage.meta.map(([k, v]) => (
                        <div key={k} className="flex items-center justify-between px-3 py-2">
                          <dt className="mono-label">{k}</dt>
                          <dd className="font-mono text-xs text-foreground">{v}</dd>
                        </div>
                      ))}
                    </dl>

                    <ul className="mt-4 space-y-1.5 border-l border-accent/60 pl-3">
                      {stage.steps.map((s, i) => (
                        <motion.li
                          key={s}
                          initial={{ opacity: 0, x: -6 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: 0.08 * i + 0.1 }}
                          className="font-mono text-xs text-muted-foreground"
                        >
                          <span className="text-accent">&gt;</span> {s}
                        </motion.li>
                      ))}
                    </ul>

                    <div className="mono-label mt-4">
                      {stage.name} // agent stage
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </div>
  );
}
