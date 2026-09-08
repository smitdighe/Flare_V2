import { useState } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { BookOpen, Play, CheckCircle2, ShieldCheck, Clock, Check, RefreshCw } from 'lucide-react';

interface PlaybookStep {
  name: string;
  detail: string;
  status: 'pending' | 'running' | 'completed';
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: string;
  steps: string[];
  lastRun: string;
  successRate: number;
  enabled: boolean;
}

const PLAYBOOKS: Playbook[] = [
  {
    id: 'PB-01',
    name: 'Automated Host Isolation & Forensic Capture',
    description: 'Triggered upon confirmed critical Malware C2 or Ransomware beaconing. Quarantines VLAN and snapshots process memory.',
    trigger: 'Severity == CRITICAL && AttackType in [malware_c2, data_exfiltration]',
    steps: [
      'Query CrowdStrike EDR for endpoint sensor ID',
      'Issue network containment command via API',
      'Trigger cloud memory dump to S3 triage bucket',
      'Notify tier-3 incident responder in Slack #war-room',
    ],
    lastRun: '1h 20m ago',
    successRate: 98.4,
    enabled: true,
  },
  {
    id: 'PB-02',
    name: 'Dynamic Edge Firewall Subnet Blackhole',
    description: 'Automates ACL block on perimeter firewalls when a distributed brute-force or high-rate SYN flood is detected.',
    trigger: 'Alert Velocity > 40/min && AttackType == ddos',
    steps: [
      'Extract top-10 source IPs from correlation cluster',
      'Validate IPs are not in corporate CDN allowlist',
      'Push temporary 4-hour drop rule to Fortinet & Palo Alto firewalls',
      'Log signed action in SOC Audit Trail',
    ],
    lastRun: '45m ago',
    successRate: 100.0,
    enabled: true,
  },
  {
    id: 'PB-03',
    name: 'Web Application Attack Auto-Sanitize & IP Ban',
    description: 'Enforces immediate Cloudflare IP challenge and updates web server modsecurity rules upon SQL injection or LFI detection.',
    trigger: 'AttackType == web_attack && MaxIOC >= 80',
    steps: [
      'Issue Cloudflare Block rule for 60 minutes',
      'Invalidate active user sessions associated with source IP',
      'Generate remediation summary for application engineering team',
    ],
    lastRun: '12m ago',
    successRate: 95.8,
    enabled: true,
  },
];

export function PlaybooksPanel() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>(PLAYBOOKS);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [runProgress, setRunProgress] = useState<number>(0);
  const [activeSteps, setActiveSteps] = useState<PlaybookStep[]>([]);

  const handleExecute = (pb: Playbook) => {
    setRunningId(pb.id);
    setRunProgress(10);
    const steps: PlaybookStep[] = pb.steps.map((st, i) => ({
      name: st,
      detail: `Step ${i + 1} of ${pb.steps.length}`,
      status: i === 0 ? 'running' : 'pending',
    }));
    setActiveSteps(steps);

    // Step progression animation
    let stepIndex = 0;
    const interval = setInterval(() => {
      stepIndex++;
      if (stepIndex < pb.steps.length) {
        setRunProgress(Math.round(((stepIndex + 1) / pb.steps.length) * 100));
        setActiveSteps((prev) =>
          prev.map((s, idx) => ({
            ...s,
            status: idx < stepIndex ? 'completed' : idx === stepIndex ? 'running' : 'pending',
          }))
        );
      } else {
        clearInterval(interval);
        setRunProgress(100);
        setActiveSteps((prev) => prev.map((s) => ({ ...s, status: 'completed' })));
        setTimeout(() => {
          setRunningId(null);
        }, 1200);
      }
    }, 700);
  };

  const togglePlaybook = (id: string) => {
    setPlaybooks((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
  };

  return (
    <div className="space-y-4">
      {/* Simulation execution banner */}
      {runningId && (
        <div className="p-4 bg-slate-900 border border-emerald-500/50 rounded-md font-mono text-xs shadow-2xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <RefreshCw size={14} className="animate-spin" />
              <span>Executing Playbook Workflow: {runningId} ({runProgress}%)</span>
            </div>
            <span className="text-dim text-[10px]">Automated Orchestration Engine</span>
          </div>

          <div className="w-full h-1.5 bg-void rounded-full overflow-hidden border border-edge/60">
            <div
              className="h-full bg-emerald-500 transition-all duration-300 shadow-[0_0_10px_#10B981]"
              style={{ width: `${runProgress}%` }}
            />
          </div>

          <div className="space-y-1.5 pt-1">
            {activeSteps.map((step) => (
              <div key={step.name} className="flex items-center justify-between text-[11px] p-2 rounded bg-void/50">
                <span className="text-slate-300">{step.name}</span>
                <span
                  className={`font-bold ${
                    step.status === 'completed'
                      ? 'text-emerald-400'
                      : step.status === 'running'
                      ? 'text-amber-400 animate-pulse'
                      : 'text-dim'
                  }`}
                >
                  {step.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <BookOpen className="text-emerald-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              Automated Response Playbooks
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
              3 Standard Operating Procedures
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Pre-approved multi-step orchestration playbooks designed to immediately contain verified threats without human latency.
          </p>
        </div>
      </div>

      {/* Playbooks list */}
      <div className="space-y-3">
        {playbooks.map((pb) => (
          <Card3D key={pb.id} intensity={3} glare={true}>
            <div className="p-5 glass-panel-3d rounded-md border border-edge/80 space-y-4">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-raised border border-edge text-dim font-bold">
                    {pb.id}
                  </span>
                  <h3 className="font-mono text-sm font-bold text-ink">{pb.name}</h3>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={() => togglePlaybook(pb.id)}
                    className={`font-mono text-[10px] font-bold px-2.5 py-1 rounded border transition-all cursor-pointer ${
                      pb.enabled
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                        : 'bg-void border-edge text-dim'
                    }`}
                  >
                    {pb.enabled ? 'ACTIVE' : 'MUTED'}
                  </button>

                  <button
                    onClick={() => handleExecute(pb)}
                    disabled={runningId !== null}
                    className="font-mono text-[11px] font-bold px-3 py-1.5 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/25 transition-all flex items-center gap-1.5 cursor-pointer shadow-[0_0_12px_rgba(16,185,129,0.2)] disabled:opacity-40"
                  >
                    <Play size={12} className="fill-current" />
                    <span>Run Playbook</span>
                  </button>
                </div>
              </div>

              <p className="text-xs text-dim leading-relaxed font-sans">{pb.description}</p>

              <div className="p-2.5 bg-void/60 rounded border border-edge font-mono text-[11px] text-slate-300">
                <span className="text-dim">Trigger Criteria: </span>
                <code className="text-emerald-400">{pb.trigger}</code>
              </div>

              {/* Steps timeline */}
              <div>
                <span className="font-mono text-[10px] text-dim uppercase tracking-wider block mb-2">
                  Execution Workflow ({pb.steps.length} Steps)
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2 font-mono text-[11px]">
                  {pb.steps.map((st, idx) => (
                    <div key={st} className="p-2.5 rounded bg-slate-900/60 border border-edge/60 flex items-start gap-2">
                      <span className="h-4 w-4 rounded-full bg-raised text-dim text-[10px] flex items-center justify-center shrink-0 font-bold">
                        {idx + 1}
                      </span>
                      <span className="text-slate-300 leading-tight">{st}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between font-mono text-[10px] text-dim pt-2 border-t border-edge/40">
                <span className="flex items-center gap-1">
                  <Clock size={11} /> Last run: {pb.lastRun}
                </span>
                <span className="flex items-center gap-1 text-emerald-400 font-bold">
                  <CheckCircle2 size={11} /> Success Rate: {pb.successRate}%
                </span>
              </div>
            </div>
          </Card3D>
        ))}
      </div>
    </div>
  );
}
