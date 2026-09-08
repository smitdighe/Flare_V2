import { useState } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { SlidersHorizontal, Plus, Check, X, ShieldAlert, Sparkles, Trash2 } from 'lucide-react';

interface TriageRule {
  id: string;
  name: string;
  condition: string;
  action: string;
  enabled: boolean;
  matchCount: number;
  lastFired: string;
}

const INITIAL_RULES: TriageRule[] = [
  {
    id: 'R-01',
    name: 'Auto-Escalate Short Port 80 Flows',
    condition: 'dest_port == 80 && flow_duration < 10000ms && pkts <= 4',
    action: 'set_severity("high") + add_tag("potential-rce")',
    enabled: true,
    matchCount: 142,
    lastFired: '2m ago',
  },
  {
    id: 'R-02',
    name: 'Tor Exit Node High Rep Block',
    condition: 'ioc_reputation >= 85 || src_ip in tor_exit_nodes',
    action: 'set_severity("critical") + trigger_playbook("isolate_host")',
    enabled: true,
    matchCount: 310,
    lastFired: 'Just now',
  },
  {
    id: 'R-03',
    name: 'Suppress Internal Nessus Scanner',
    condition: 'src_ip == "10.0.0.5" && signature contains "Scanner"',
    action: 'set_severity("info") + suppress_notification()',
    enabled: true,
    matchCount: 98,
    lastFired: '18m ago',
  },
  {
    id: 'R-04',
    name: 'SynFlood Defense Rate Floor',
    condition: 'attack_type == "ddos" && pps > 500',
    action: 'set_severity("critical") + enable_syn_cookie()',
    enabled: false,
    matchCount: 45,
    lastFired: '1h ago',
  },
];

export function RulesPanel() {
  const [rules, setRules] = useState<TriageRule[]>(INITIAL_RULES);
  const [modalOpen, setModalOpen] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [newCondition, setNewCondition] = useState('');
  const [newAction, setNewAction] = useState('set_severity("high")');

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const deleteRule = (id: string) => {
    setRules((prev) => prev.filter((r) => r.id !== id));
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim()) return;
    const rule: TriageRule = {
      id: `R-0${rules.length + 1}`,
      name: newRuleName,
      condition: newCondition || 'src_ip in internal_subnets',
      action: newAction,
      enabled: true,
      matchCount: 0,
      lastFired: 'Never',
    };
    setRules([rule, ...rules]);
    setNewRuleName('');
    setNewCondition('');
    setModalOpen(false);
  };

  return (
    <div className="space-y-4">
      {/* Create Rule Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-2xl relative font-mono text-xs">
            <button
              onClick={() => setModalOpen(false)}
              className="absolute top-4 right-4 text-dim hover:text-ink cursor-pointer"
            >
              <X size={16} />
            </button>
            <div className="flex items-center gap-2">
              <Sparkles className="text-cyan-400" size={18} />
              <h3 className="font-bold text-sm text-ink uppercase tracking-wider">Create Triage Rule</h3>
            </div>
            <form onSubmit={handleCreateRule} className="space-y-3 pt-2 border-t border-edge/60">
              <div>
                <label className="text-dim text-[10px] uppercase block mb-1">Rule Name</label>
                <input
                  type="text"
                  placeholder="e.g. Detect Outbound Cobalt Strike Beacon"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  className="w-full px-3 py-1.5 bg-void/80 border border-edge rounded font-mono text-ink text-xs focus:outline-none focus:border-cyan-400"
                  required
                />
              </div>

              <div>
                <label className="text-dim text-[10px] uppercase block mb-1">Match Condition (Predicate Expression)</label>
                <input
                  type="text"
                  placeholder='e.g. attack_type == "malware_c2" && dest_port in [443, 8443]'
                  value={newCondition}
                  onChange={(e) => setNewCondition(e.target.value)}
                  className="w-full px-3 py-1.5 bg-void/80 border border-edge rounded font-mono text-ink text-xs focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-dim text-[10px] uppercase block mb-1">Triggered Action</label>
                <select
                  value={newAction}
                  onChange={(e) => setNewAction(e.target.value)}
                  className="w-full px-3 py-1.5 bg-void/80 border border-edge rounded font-mono text-ink text-xs focus:outline-none focus:border-cyan-400"
                >
                  <option value='set_severity("critical") + trigger_playbook("isolate_host")'>
                    Set Severity Critical + Auto-Isolate
                  </option>
                  <option value='set_severity("high") + add_tag("review_required")'>
                    Set Severity High + Tag Review
                  </option>
                  <option value='set_severity("info") + suppress_notification()'>
                    Suppress & Demote to Info
                  </option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-raised border border-edge text-dim hover:text-ink"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 font-bold text-white shadow-[0_0_12px_rgba(6,182,212,0.4)]"
                >
                  Save & Activate Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <SlidersHorizontal className="text-cyan-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              Deterministic Detection & Triage Rules
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold">
              {rules.filter((r) => r.enabled).length} Active Rules
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Declarative rules executed prior to LLM reasoning. Rules take precedence and can override model verdicts or trigger automations.
          </p>
        </div>

        <button
          onClick={() => setModalOpen(true)}
          className="font-mono text-[11px] font-bold px-3 py-1.5 rounded-md bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/25 transition-all flex items-center gap-1.5 cursor-pointer shadow-[0_0_12px_rgba(6,182,212,0.2)]"
        >
          <Plus size={13} />
          <span>New Rule</span>
        </button>
      </div>

      {/* Rules List */}
      <div className="space-y-3">
        {rules.map((rule) => (
          <Card3D key={rule.id} intensity={3} glare={true}>
            <div className="p-4 glass-panel-3d rounded-md border border-edge/80 flex items-center justify-between gap-4 flex-wrap">
              <div className="space-y-1.5 max-w-2xl">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-raised border border-edge text-dim font-bold">
                    {rule.id}
                  </span>
                  <span className="font-mono text-xs font-bold text-ink">{rule.name}</span>
                </div>

                <div className="font-mono text-[11px] text-slate-300 bg-void/50 px-2.5 py-1 rounded border border-edge/60">
                  <span className="text-dim">IF </span>
                  <code className="text-cyan-300">{rule.condition}</code>
                </div>

                <div className="font-mono text-[11px] text-dim flex items-center gap-2">
                  <span>THEN: <strong className="text-amber-400">{rule.action}</strong></span>
                  <span>·</span>
                  <span>Matches: <strong className="text-ink">{rule.matchCount}</strong></span>
                  <span>·</span>
                  <span>Last fired: {rule.lastFired}</span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => toggleRule(rule.id)}
                  className={`font-mono text-[10px] font-bold px-3 py-1.5 rounded border transition-all cursor-pointer flex items-center gap-1.5 ${
                    rule.enabled
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.2)]'
                      : 'bg-void border-edge text-dim hover:text-ink'
                  }`}
                >
                  {rule.enabled ? <Check size={12} /> : <X size={12} />}
                  <span>{rule.enabled ? 'ACTIVE' : 'DISABLED'}</span>
                </button>

                <button
                  onClick={() => deleteRule(rule.id)}
                  className="p-1.5 rounded text-dim hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
                  title="Delete Rule"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          </Card3D>
        ))}
      </div>
    </div>
  );
}
