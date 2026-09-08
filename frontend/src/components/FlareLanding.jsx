import { ArrowUpRight, ArrowDown, Terminal, Cpu } from 'lucide-react';
import { Magnetic, Reveal, TiltPanel, CountUp } from './landing/Primitives.jsx';
import { StageCards } from './landing/StageCards.jsx';
import { CapabilitiesBento } from './landing/CapabilitiesBento.jsx';
import { TriageBuffer } from './landing/TriageBuffer.jsx';

export default function FlareLanding({ onLaunch }) {
  return (
    <div className="relative min-h-screen overflow-x-clip bg-background selection:bg-primary/20 selection:text-primary">

      {/* Clean Minimalist Background Mesh */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 h-[500px] w-[720px] rounded-full bg-primary/10 blur-[160px]" />
        <div className="absolute top-1/3 -right-40 h-[600px] w-[600px] rounded-full bg-sky-600/5 blur-[170px]" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff03_1px,transparent_1px),linear-gradient(to_bottom,#ffffff03_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-60" />
        <div className="absolute inset-x-0 bottom-0 h-48 bg-gradient-to-t from-background via-background/80 to-transparent" />
      </div>

      {/* Docked Minimalist Header */}
      <header className="sticky top-0 z-40 mx-auto w-full border-b border-border/40 bg-background/70 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1400px] items-center justify-between px-6 py-4 md:px-12">
          <a href="/" className="group flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border/80 bg-secondary/30 transition-colors group-hover:border-primary/60 group-hover:bg-primary/10">
              <img src="/flare-logo.png" alt="Flare" className="h-4 w-4 object-contain" />
            </div>
            <span className="font-mono text-xs font-semibold tracking-[0.24em] text-foreground">
              FLARE <span className="text-muted-foreground font-normal">// ENGINE</span>
            </span>
          </a>
          <nav className="hidden items-center gap-8 md:flex">
            {[['pipeline', '#pipeline'], ['capabilities', '#capabilities'], ['command center', '#command-center'], ['brief', '#brief']].map(([label, href]) => (
              <a key={label} href={href} className="font-mono text-xs uppercase tracking-[0.16em] text-muted-foreground transition-colors hover:text-foreground">
                {label}
              </a>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <Magnetic href="/login" strength={6} className="flex items-center gap-1.5 rounded-full border border-border/80 bg-secondary/30 px-4 py-2 font-mono text-xs uppercase tracking-[0.12em] text-foreground/90 backdrop-blur transition-all hover:border-primary/60 hover:bg-primary/10 hover:text-primary">
              <span>opening engine</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Magnetic>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative z-20 mx-auto max-w-[1400px] px-6 pb-24 pt-16 md:px-12 md:pt-28">
        <div className="grid items-start gap-16 lg:grid-cols-[1.1fr_0.9fr]">
          <div>
            <Reveal>
              <div className="mb-6 inline-flex items-center gap-2.5 rounded-full border border-primary/30 bg-primary/10 px-3.5 py-1.5 backdrop-blur-md">
                <span className="h-1.5 w-1.5 rounded-full bg-signal animate-blink" />
                <span className="font-mono text-[11px] font-medium uppercase tracking-[0.18em] text-primary">
                  system: flare v2.4 // operational
                </span>
              </div>
            </Reveal>

            <h1 className="font-display text-[clamp(2.8rem,7vw,5.4rem)] font-bold tracking-tight text-foreground leading-[1.02]">
              {['Triage at the speed', 'of the signal.'].map((line, i) => (
                <Reveal key={line} delay={i * 140}>
                  <span className="block">{line}</span>
                </Reveal>
              ))}
            </h1>

            <Reveal delay={280}>
              <p className="mt-7 max-w-lg text-[16px] leading-relaxed text-muted-foreground font-normal">
                Flare is a multi-agent security engine for teams that need the verdict, the
                evidence, and the next move before the noise compounds.
              </p>
            </Reveal>

            <Reveal delay={380}>
              <div className="mt-10 flex flex-wrap items-center gap-4">
                <Magnetic href="/login" className="flex items-center gap-2 rounded-lg bg-primary px-6 py-3.5 font-mono text-xs font-semibold uppercase tracking-[0.14em] text-primary-foreground shadow-[0_0_24px_rgba(245,158,11,0.25)] transition-all hover:bg-primary/90 hover:shadow-[0_0_32px_rgba(245,158,11,0.4)]">
                  initiate deployment <ArrowUpRight className="h-3.5 w-3.5" />
                </Magnetic>
                <Magnetic href="#brief" strength={6} className="flex items-center gap-2 rounded-lg border border-border/80 bg-card/40 px-6 py-3.5 font-mono text-xs uppercase tracking-[0.14em] text-foreground/80 backdrop-blur-md transition-colors hover:border-primary/50 hover:text-foreground">
                  read the brief <ArrowDown className="h-3.5 w-3.5 opacity-60" />
                </Magnetic>
              </div>
            </Reveal>

            <Reveal delay={480}>
              <div className="mt-14 grid max-w-md grid-cols-3 divide-x divide-border/60 rounded-xl border border-border/60 bg-card/40 backdrop-blur-lg">
                {[
                  ['f1 score', <CountUp key="a" to={0.613} decimals={3} />],
                  ['tests green', <CountUp key="b" to={33} />],
                  ['agents', <CountUp key="c" to={3} />],
                ].map(([label, node]) => (
                  <div key={String(label)} className="p-4">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
                    <div className="mt-1.5 font-mono text-2xl font-semibold text-primary">{node}</div>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>

          {/* Interactive Telemetry Card */}
          <Reveal delay={200} variant="scale">
            <TiltPanel className="glass-card rounded-2xl p-6 shadow-2xl">
              <div className="flex items-center justify-between border-b border-border/40 pb-4">
                <span className="font-mono text-xs uppercase tracking-[0.18em] text-foreground font-semibold flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 text-primary" />
                  field telemetry
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-signal/40 bg-signal/10 px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-signal font-medium">
                  <span className="h-1.5 w-1.5 rounded-full bg-signal animate-blink" /> live
                </span>
              </div>

              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                {[
                  ['accuracy metric', '0.613', 'F1 // CICIDS2017'],
                  ['triage latency', '<1s', 'classifier + context'],
                ].map(([label, value, sub]) => (
                  <div key={label} className="group rounded-xl border border-border/40 bg-card/60 p-4 transition-all hover:border-primary/40 hover:bg-card/90">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
                    <div className="mt-2 font-mono text-3xl font-semibold text-primary transition-transform duration-300 group-hover:translate-x-1">{value}</div>
                    <div className="mt-1 font-mono text-[10px] text-muted-foreground/80">{sub}</div>
                  </div>
                ))}
              </div>

              <div className="mt-3 flex items-center justify-between rounded-xl border border-border/40 bg-card/60 p-4">
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">active modules</div>
                  <div className="mt-1.5 font-mono text-xs tracking-wider text-foreground font-semibold flex items-center gap-2">
                    <Cpu className="h-3 w-3 text-primary" />
                    CLASSIFY → ENRICH → REASON
                  </div>
                </div>
                <div className="flex gap-1.5">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <span key={i} className={`h-2 w-2 rounded-full ${i < 4 ? 'bg-primary shadow-[0_0_6px_rgba(245,158,11,0.5)]' : 'bg-border'}`} />
                  ))}
                </div>
              </div>

              <ul className="mt-5 space-y-2 border-l-2 border-primary/40 pl-4">
                {['raw event arrives', 'agents isolate the meaningful parts', 'analyst gets a bounded decision'].map((l) => (
                  <li key={l} className="font-mono text-[11px] text-muted-foreground flex items-center gap-2">
                    <span className="text-primary font-bold">›</span>
                    <span>{l}</span>
                  </li>
                ))}
              </ul>
            </TiltPanel>
          </Reveal>
        </div>
      </section>


      {/* Pipeline Operating Model */}
      <section id="pipeline" className="relative z-20 mx-auto max-w-[1400px] px-6 py-28 md:px-12">
        <div className="grid gap-12 lg:grid-cols-[1fr_1fr]">
          <Reveal variant="left">
            <span className="font-mono text-xs uppercase tracking-[0.2em] text-primary font-semibold">the operating model</span>
            <h2 className="font-display mt-4 text-[clamp(2rem,4vw,3.2rem)] font-bold tracking-tight text-foreground leading-[1.1]">
              Three passes. One<br />clear answer.
            </h2>
          </Reveal>
          <Reveal delay={140}>
            <p className="max-w-md text-[15px] leading-relaxed text-muted-foreground lg:mt-12">
              The pipeline is deliberately linear. Each stage removes a different kind of
              uncertainty — open a stage to see exactly what it does and what it hands forward.
            </p>
          </Reveal>
        </div>
        <div className="mt-12">
          <StageCards />
        </div>
      </section>

      {/* Capabilities Asymmetric Bento Grid */}
      <CapabilitiesBento />

      {/* Command Center Showcase */}
      <section id="command-center" className="relative z-20 mx-auto max-w-[1400px] border-t border-border/40 px-6 py-28 md:px-12">
        <div className="grid items-center gap-16 lg:grid-cols-[0.9fr_1.1fr]">
          <div>
            <Reveal variant="left">
              <span className="font-mono text-xs uppercase tracking-[0.2em] text-primary font-semibold">inside the command center</span>
              <h2 className="font-display mt-4 text-[clamp(2rem,4vw,3.2rem)] font-bold tracking-tight text-foreground leading-[1.1]">
                The dashboard does not<br />ask you to admire it.
              </h2>
            </Reveal>
            <Reveal delay={140}>
              <p className="mt-6 max-w-md text-[15px] leading-relaxed text-muted-foreground">
                It puts the alert queue, context, and recommended action in the same line of sight.
                Signal first. Ceremony second.
              </p>
            </Reveal>
            <Reveal delay={240}>
              <ul className="mt-8 space-y-3.5">
                {[
                  'focus rows with j / k',
                  'inspect evidence without losing your place',
                  'keep critical activity visible',
                ].map((l) => (
                  <li key={l} className="group flex items-center gap-3">
                    <span className="h-2 w-2 rounded-full bg-primary/80 transition-transform duration-300 group-hover:scale-125" />
                    <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground transition-colors group-hover:text-foreground">{l}</span>
                  </li>
                ))}
              </ul>
            </Reveal>
          </div>
          <Reveal delay={180} variant="scale">
            <TiltPanel max={4} className="glass-card rounded-2xl p-1 shadow-2xl">
              <TriageBuffer />
            </TiltPanel>
          </Reveal>
        </div>
      </section>

      {/* Command Brief Final CTA */}
      <section id="brief" className="relative z-20 mx-auto max-w-[1400px] border-t border-border/40 px-6 py-28 md:px-12">
        <Reveal>
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-primary font-semibold">the command brief</span>
        </Reveal>
        <div className="mt-8 grid items-end gap-14 lg:grid-cols-[1fr_1fr]">
          <Reveal delay={120} variant="left">
            <h2 className="font-display text-[clamp(2.4rem,6vw,4.4rem)] font-bold tracking-tight leading-[1.05]">
              Less noise.<br />
              <span className="bg-gradient-to-r from-primary via-amber-400 to-orange-400 bg-clip-text text-transparent">
                More agency.
              </span>
            </h2>
          </Reveal>
          <Reveal delay={240}>
            <div>
              <p className="max-w-md text-[15px] leading-relaxed text-muted-foreground">
                Bring the live feed into focus, let the agents do the first pass, and keep the
                decision surface readable for the person who owns the incident.
              </p>
              <div className="mt-8">
                <Magnetic href="/login" className="inline-flex items-center gap-2 rounded-lg bg-primary px-7 py-4 font-mono text-xs font-semibold uppercase tracking-[0.14em] text-primary-foreground shadow-[0_0_24px_rgba(245,158,11,0.25)] transition-all hover:bg-primary/90 hover:shadow-[0_0_32px_rgba(245,158,11,0.4)]">
                  open flare command center <ArrowUpRight className="h-3.5 w-3.5" />
                </Magnetic>
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* Clean Minimalist Footer */}
      <footer className="relative z-20 mx-auto flex max-w-[1400px] flex-col gap-4 border-t border-border/40 px-6 py-8 md:flex-row md:items-center md:justify-between md:px-12">
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">flare // multi-agent security engine</span>
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground/80">classify / enrich / reason</span>
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground/80">build 2.4.0-stable</span>
      </footer>
    </div>
  );
}
