import { useState } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { Bell, Mail, Send, Check, MessageSquare, AlertOctagon, CheckCircle2 } from 'lucide-react';

interface ChannelConfig {
  id: string;
  name: string;
  type: 'Email' | 'Slack' | 'PagerDuty' | 'Webhook';
  target: string;
  enabled: boolean;
  minSeverity: 'critical' | 'high' | 'medium';
}

const CHANNELS: ChannelConfig[] = [
  {
    id: 'CH-01',
    name: 'SOC Primary Email Dispatch',
    type: 'Email',
    target: 'soc-alerts@flare.dev',
    enabled: true,
    minSeverity: 'high',
  },
  {
    id: 'CH-02',
    name: 'Slack #secops-critical Feed',
    type: 'Slack',
    target: 'https://hooks.slack.com/services/T00/B00/X00',
    enabled: true,
    minSeverity: 'critical',
  },
  {
    id: 'CH-03',
    name: 'PagerDuty On-Call Escalation',
    type: 'PagerDuty',
    target: 'Service Key: pd-flare-prod-9921',
    enabled: true,
    minSeverity: 'critical',
  },
  {
    id: 'CH-04',
    name: 'SIEM Webhook Ingest Relay',
    type: 'Webhook',
    target: 'https://siem.corp.internal/v1/events',
    enabled: false,
    minSeverity: 'medium',
  },
];

export function NotificationsPanel() {
  const [channels, setChannels] = useState<ChannelConfig[]>(CHANNELS);
  const [testSent, setTestSent] = useState<string | null>(null);
  const [debounceSeconds, setDebounceSeconds] = useState(300);

  const toggleChannel = (id: string) => {
    setChannels((prev) =>
      prev.map((c) => (c.id === id ? { ...c, enabled: !c.enabled } : c))
    );
  };

  const sendTest = (ch: ChannelConfig) => {
    setTestSent(ch.id);
    setTimeout(() => {
      setTestSent(null);
    }, 2500);
  };

  return (
    <div className="space-y-4">
      {/* Toast */}
      {testSent && (
        <div className="fixed top-12 right-6 z-50 p-3 bg-slate-900 border border-emerald-500 rounded-md shadow-2xl font-mono text-xs text-ink flex items-center gap-2 animate-bounce">
          <CheckCircle2 size={16} className="text-emerald-400" />
          <span>Test alert successfully dispatched to channel {testSent}!</span>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <Bell className="text-amber-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              Alert Routing & Notification Matrix
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 font-bold">
              {channels.filter((c) => c.enabled).length} Active Dispatch Routes
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Configure multi-channel outbound alerts. Presence-aware dispatch suppresses emails if an operator is actively viewing the live feed tab.
          </p>
        </div>
      </div>

      {/* Presence & Throttle Settings */}
      <Card3D intensity={3} glare={false}>
        <div className="p-4 glass-panel-3d rounded-md border border-edge/80 space-y-3">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div>
              <span className="font-mono text-xs font-bold text-ink uppercase tracking-wider block">
                Presence-Aware Notification Dispatch
              </span>
              <p className="text-[11px] text-dim mt-0.5">
                Suppresses noisy email digests when your browser tab has active WebSocket presence (active within 15 minutes).
              </p>
            </div>
            <span className="font-mono text-[10px] px-2.5 py-1 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 font-bold">
              PRESENCE GUARD ACTIVE
            </span>
          </div>

          <div className="pt-2 border-t border-edge/40 flex items-center justify-between gap-4 flex-wrap text-xs font-mono">
            <span className="text-dim">Digest Debounce Window:</span>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={60}
                max={900}
                step={60}
                value={debounceSeconds}
                onChange={(e) => setDebounceSeconds(Number(e.target.value))}
                className="w-36 accent-amber-400 cursor-pointer"
              />
              <span className="font-bold text-ink tabular-nums">{debounceSeconds / 60} minutes</span>
            </div>
          </div>
        </div>
      </Card3D>

      {/* Channels List */}
      <div className="space-y-3">
        {channels.map((ch) => (
          <Card3D key={ch.id} intensity={3} glare={true}>
            <div className="p-4 glass-panel-3d rounded-md border border-edge/80 flex items-center justify-between gap-4 flex-wrap">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  {ch.type === 'Email' ? (
                    <Mail size={15} className="text-blue-400" />
                  ) : ch.type === 'Slack' ? (
                    <MessageSquare size={15} className="text-emerald-400" />
                  ) : (
                    <AlertOctagon size={15} className="text-red-400" />
                  )}
                  <span className="font-mono text-xs font-bold text-ink">{ch.name}</span>
                  <span className="font-mono text-[9px] px-2 py-0.5 rounded bg-raised border border-edge text-dim uppercase">
                    {ch.type}
                  </span>
                </div>

                <div className="font-mono text-xs text-dim">
                  <span>Destination: <strong className="text-slate-200">{ch.target}</strong></span>
                </div>

                <div className="font-mono text-[11px] text-dim flex items-center gap-2">
                  <span>Minimum Severity: </span>
                  <span
                    className={`font-bold uppercase ${
                      ch.minSeverity === 'critical'
                        ? 'text-red-400'
                        : ch.minSeverity === 'high'
                        ? 'text-amber-400'
                        : 'text-blue-400'
                    }`}
                  >
                    {ch.minSeverity}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => sendTest(ch)}
                  disabled={!ch.enabled}
                  className="font-mono text-[10px] font-bold px-3 py-1.5 rounded bg-void border border-edge text-dim hover:text-ink hover:border-edge-bright transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40"
                >
                  <Send size={11} />
                  <span>Send Test</span>
                </button>

                <button
                  onClick={() => toggleChannel(ch.id)}
                  className={`font-mono text-[10px] font-bold px-3 py-1.5 rounded border transition-all cursor-pointer flex items-center gap-1.5 ${
                    ch.enabled
                      ? 'bg-amber-500/15 border-amber-500/40 text-amber-400'
                      : 'bg-void border-edge text-dim'
                  }`}
                >
                  {ch.enabled ? <Check size={12} /> : null}
                  <span>{ch.enabled ? 'ACTIVE' : 'MUTED'}</span>
                </button>
              </div>
            </div>
          </Card3D>
        ))}
      </div>
    </div>
  );
}
