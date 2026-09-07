import { ArrowUpRight, ArrowDown, Activity, Zap, Layers } from 'lucide-react';
import { Globe } from './landing/Globe.jsx';
import { CursorField } from './landing/CursorField.jsx';
import { Magnetic, Reveal, TiltPanel, CountUp, Scramble, Parallax } from './landing/Primitives.jsx';
import { StageCards } from './landing/StageCards.jsx';
import { TriageBuffer } from './landing/TriageBuffer.jsx';
import { useScrollProgress } from '../hooks/use-reveal.js';

const TICKER = [
  'classify', 'enrich', 'reason', 'mitre att&ck grounded',
  'websocket live feed', 'abuseipdb', 'virustotal', 'langgraph pipeline',
];

const CAPABILITIES = [
  {
    icon: Activity, label: 'live feed', title: 'Streaming, not polling.',
    body: 'WebSocket + SSE push every verdict to the console the moment the pipeline settles.',
  },
  {
    icon: Zap, label: 'sub-second', title: 'Triage before the noise compounds.',
    body: 'Classification and context land in the same breath, so the queue never gets ahead of you.',
  },
  {
    icon: Layers, label: 'grounded', title: 'Evidence attached to every call.',
    body: 'Each verdict carries the reputation data and the ATT&CK technique it was reasoned from.',
  },
];

export default function FlareLanding({ onLaunch }) {
  const progress = useScrollProgress();

  return (
    <div className="relative min-h-screen overflow-x-clip bg-background">
      <CursorField />

      {/* persistent background field */}
      <div className="pointer-events-none fixed inset-0 z-0">
        <div className="tri-field absolute inset-0 opacity-70" />
        <div className="tri-glow absolute inset-0" />
        <Globe className="absolute right-[-24%] top-[8%] h-[64vh] w-[64vh] opacity-50 md:right-[-14%] md:top-[10%] md:h-[86vh] md:w-[86vh] md:opacity-65" />
        <div className="absolute inset-0" style={{ background: 'radial-gradient(ellipse 60% 50% at 18% 8%, oklch(0.26 0.05 55 / 24%), transparent 70%)' }} />
        <div className="absolute inset-x-0 bottom-0 h-40" style={{ background: 'linear-gradient(to top, var(--background), transparent)' }} />
      </div>

      {/* scroll rail */}
      <div className="fixed left-0 top-0 z-40 h-0.5 w-full bg-transparent">
        <div className="h-full bg-accent transition-[width] duration-150" style={{ width: `${progress * 100}%`, boxShadow: '0 0 14px var(--accent)' }} />
      </div>
      <span className="label fixed left-4 top-1/2 z-40 hidden -translate-y-1/2 md:block" style={{ writingMode: 'vertical-rl' }}>
        scroll / {String(Math.round(progress * 100)).padStart(3, '0')}%
      </span>

      {/* nav */}
      <header className="relative z-30 mx-auto flex max-w-[1400px] items-center justify-between px-6 py-6 md:px-12">
        <a href="/" className="group flex items-center gap-3">
          <span className="flex h-6 w-6 items-center justify-center border border-accent/60 text-accent transition-transform duration-500 group-hover:rotate-90">
            <span className="text-[10px]">&#9654;</span>
          </span>
          <span className="font-mono text-xs tracking-[0.28em] text-foreground">
            FLARE <span className="text-muted-foreground">// ENGINE</span>
          </span>
        </a>
        <nav className="hidden gap-8 md:flex">
          {[['pipeline', '#pipeline'], ['capabilities', '#capabilities'], ['command center', '#command-center'], ['brief', '#brief']].map(([label, href]) => (
            <a key={label} href={href} className="label transition-colors hover:text-accent">{label}</a>
          ))}
        </nav>
        <Magnetic href="/login" strength={6} className="label border border-border px-4 py-2.5 text-foreground/80 transition-colors hover:border-accent/60 hover:text-accent">
          opening engine &#8599;
        </Magnetic>
      </header>

      {/* hero */}
      <section className="relative z-20 mx-auto max-w-[1400px] px-6 pb-24 pt-16 md:px-12 md:pt-24">
        <div className="grid items-start gap-16 lg:grid-cols-[1.05fr_0.95fr]">
          <div>
            <Reveal>
              <div className="mb-8 flex items-center gap-4">
                <span className="h-px w-10 bg-accent" />
                <span className="label text-signal-ok"><Scramble text="system: flare v2.4 // operational" /></span>
              </div>
            </Reveal>

            <h1 className="display text-[clamp(2.9rem,7.5vw,5.6rem)] text-foreground">
              {['Triage at the speed', 'of the signal.'].map((line, i) => (
                <Reveal key={line} delay={i * 160}><span className="block">{line}</span></Reveal>
              ))}
            </h1>

            <Reveal delay={300}>
              <p className="mt-8 max-w-md text-[15px] leading-relaxed text-muted-foreground">
                Flare is a multi-agent security engine for teams that need the verdict, the
                evidence, and the next move before the noise compounds.
                <span className="ml-1 inline-block h-3.5 w-2 translate-y-0.5 animate-blink bg-accent" />
              </p>
            </Reveal>

            <Reveal delay={400}>
              <div className="mt-10 flex flex-wrap items-center gap-3">
                <Magnetic href="/login" className="label bg-accent px-6 py-3.5 text-accent-foreground">
                  initiate deployment <ArrowUpRight className="h-3.5 w-3.5" />
                </Magnetic>
                <Magnetic href="#brief" strength={6} className="label border border-border px-6 py-3.5 text-foreground/80 transition-colors hover:border-accent/60 hover:text-accent">
                  read the brief <ArrowDown className="h-3.5 w-3.5 animate-drift" />
                </Magnetic>
              </div>
            </Reveal>

            <Reveal delay={520}>
              <div className="mt-14 grid max-w-md grid-cols-3 gap-px border border-border bg-border">
                {[
                  ['f1 score', <CountUp key="a" to={0.613} decimals={3} />],
                  ['tests green', <CountUp key="b" to={33} />],
                  ['agents', <CountUp key="c" to={3} />],
                ].map(([label, node], i) => (
                  <div key={String(label)} className="bg-card/60 p-4" style={{ transitionDelay: `${i * 80}ms` }}>
                    <div className="label">{label}</div>
                    <div className="mt-2 font-display text-2xl text-accent">{node}</div>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>

          <Reveal delay={220} variant="scale" className="animate-drift">
            <TiltPanel className="panel rounded-md p-5">
              <div className="flex items-center justify-between">
                <span className="label">field telemetry</span>
                <span className="label flex items-center gap-2 text-signal-ok">
                  <span className="h-1.5 w-1.5 animate-blink rounded-full bg-signal-ok" /> live
                </span>
              </div>
              <div className="mt-5 grid gap-px border border-border bg-border sm:grid-cols-2">
                {[
                  ['accuracy metric', '0.613', 'F1 // CICIDS2017'],
                  ['triage latency', '<1s', 'classifier + context'],
                ].map(([label, value, sub]) => (
                  <div key={label} className="group bg-card/70 p-5 transition-colors hover:bg-card">
                    <div className="label">{label}</div>
                    <div className="mt-3 font-display text-3xl text-accent transition-transform duration-500 group-hover:translate-x-1">{value}</div>
                    <div className="mt-2 font-mono text-[10px] text-muted-foreground">{sub}</div>
                  </div>
                ))}
              </div>
              <div className="mt-px flex items-center justify-between border border-border bg-card/70 p-5">
                <div>
                  <div className="label">active modules</div>
                  <div className="mt-3 font-mono text-xs tracking-[0.14em] text-foreground">
                    <Scramble text="CLASSIFY → ENRICH → REASON" />
                  </div>
                </div>
                <div className="flex gap-1">
                  {Array.from({ length: 7 }).map((_, i) => (
                    <span key={i} className={`h-2.5 w-2.5 ${i < 5 ? 'bg-accent animate-blink' : 'border border-border'}`} style={{ opacity: i < 5 ? 1 - i * 0.1 : 1, animationDelay: `${i * 220}ms` }} />
                  ))}
                </div>
              </div>
              <ul className="mt-5 space-y-2 border-l border-accent/50 pl-4">
                {['raw event arrives', 'agents isolate the meaningful parts', 'analyst gets a bounded decision'].map((l, i) => (
                  <li key={l} className="font-mono text-[11px] text-muted-foreground">
                    <span className="text-accent">&gt;</span> <span style={{ animationDelay: `${i * 400}ms` }}>{l}</span>
                  </li>
                ))}
              </ul>
            </TiltPanel>
          </Reveal>
        </div>
      </section>

      {/* marquee */}
      <div className="relative z-20 overflow-hidden border-y border-border bg-card/30 py-3">
        <div className="flex w-max animate-ticker gap-10">
          {[...TICKER, ...TICKER, ...TICKER, ...TICKER].map((w, i) => (
            <span key={`${w}-${i}`} className="label whitespace-nowrap">{w} <span className="text-accent">/</span></span>
          ))}
        </div>
      </div>

      {/* pipeline */}
      <section id="pipeline" className="relative z-20 mx-auto max-w-[1400px] px-6 py-28 md:px-12">
        <div className="grid gap-12 lg:grid-cols-[1fr_1fr]">
          <Reveal variant="left">
            <span className="label text-accent">the operating model</span>
            <h2 className="display mt-5 text-[clamp(2rem,4vw,3.2rem)]">Three passes. One<br />clear answer.</h2>
          </Reveal>
          <Reveal delay={160}>
            <p className="max-w-md text-[15px] leading-relaxed text-muted-foreground lg:mt-14">
              The pipeline is deliberately linear. Each stage removes a different kind of
              uncertainty — open a stage to see exactly what it does and what it hands forward.
            </p>
          </Reveal>
        </div>
        <StageCards />
      </section>

      {/* capabilities */}
      <section id="capabilities" className="relative z-20 mx-auto max-w-[1400px] px-6 pb-28 md:px-12">
        <Reveal><span className="label text-accent">what it gives you</span></Reveal>
        <div className="mt-10 grid gap-px bg-border md:grid-cols-3">
          {CAPABILITIES.map((c, i) => (
            <Reveal key={c.title} delay={i * 220} variant="scale">
              <Parallax amount={18 + i * 14}>
                <div className="group relative h-full overflow-hidden bg-card/60 p-8 transition-colors duration-500 hover:bg-card">
                  <span aria-hidden className="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full opacity-0 blur-2xl transition-opacity duration-700 group-hover:opacity-100" style={{ background: 'var(--gradient-ember)' }} />
                  <c.icon className="relative h-4 w-4 text-accent transition-transform duration-500 group-hover:scale-125" />
                  <div className="label relative mt-6">{c.label}</div>
                  <h3 className="display relative mt-3 text-lg">{c.title}</h3>
                  <p className="relative mt-3 text-sm leading-relaxed text-muted-foreground">{c.body}</p>
                </div>
              </Parallax>
            </Reveal>
          ))}
        </div>
      </section>

      {/* command center */}
      <section id="command-center" className="relative z-20 mx-auto max-w-[1400px] border-t border-border px-6 py-28 md:px-12">
        <div className="grid items-center gap-16 lg:grid-cols-[0.9fr_1.1fr]">
          <div>
            <Reveal variant="left">
              <span className="label text-accent">inside the command center</span>
              <h2 className="display mt-5 text-[clamp(2rem,4vw,3.2rem)]">The dashboard does not<br />ask you to admire it.</h2>
            </Reveal>
            <Reveal delay={160}>
              <p className="mt-7 max-w-md text-[15px] leading-relaxed text-muted-foreground">
                It puts the alert queue, context, and recommended action in the same line of sight.
                Signal first. Ceremony second.
              </p>
            </Reveal>
            <Reveal delay={280}>
              <ul className="mt-9 space-y-3">
                {[
                  ['focus rows with j / k', 'oklch(0.82 0.16 78)'],
                  ['inspect evidence without losing your place', 'oklch(0.76 0.175 55)'],
                  ['keep critical activity visible', 'oklch(0.68 0.19 38)'],
                ].map(([l, c], i) => (
                  <li key={l} className="group flex items-center gap-3">
                    <span className="h-2 w-2 transition-transform duration-500 group-hover:scale-150" style={{ background: c, boxShadow: `0 0 12px ${c}`, transitionDelay: `${i * 40}ms` }} />
                    <span className="label text-foreground/70 transition-colors group-hover:text-foreground">{l}</span>
                  </li>
                ))}
              </ul>
            </Reveal>
          </div>
          <Reveal delay={220} variant="scale">
            <TiltPanel max={4}>
              <TriageBuffer />
            </TiltPanel>
          </Reveal>
        </div>
      </section>

      {/* brief */}
      <section id="brief" className="relative z-20 mx-auto max-w-[1400px] border-t border-border px-6 py-28 md:px-12">
        <Reveal><span className="label text-accent">the command brief</span></Reveal>
        <div className="mt-8 grid items-end gap-14 lg:grid-cols-[1fr_1fr]">
          <Reveal delay={140} variant="left">
            <h2 className="display text-[clamp(2.4rem,6vw,4.6rem)]">
              Less noise.<br /><span className="ember-text">More agency.</span>
            </h2>
          </Reveal>
          <Reveal delay={280}>
            <div>
              <p className="max-w-md text-[15px] leading-relaxed text-muted-foreground">
                Bring the live feed into focus, let the agents do the first pass, and keep the
                decision surface readable for the person who owns the incident.
              </p>
              <Magnetic href="/login" className="label mt-10 inline-flex bg-accent px-7 py-4 text-accent-foreground">
                open flare command center <ArrowUpRight className="h-3.5 w-3.5" />
              </Magnetic>
            </div>
          </Reveal>
        </div>
      </section>

      <footer className="relative z-20 mx-auto flex max-w-[1400px] flex-col gap-3 border-t border-border px-6 py-8 md:flex-row md:items-center md:justify-between md:px-12">
        <span className="label">flare // multi-agent security engine</span>
        <span className="label">classify / enrich / reason</span>
        <span className="label">build 2.4.0-stable</span>
      </footer>
    </div>
  );
}
