import { useState, useMemo } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { ScrollText, Search, ShieldCheck, Download, Eye, X } from 'lucide-react';

interface AuditEntry {
  id: string;
  timestamp: string;
  operator: string;
  action: 'RULE_FIRED' | 'PLAYBOOK_TRIGGERED' | 'SEVERITY_OVERRIDE' | 'USER_LOGIN' | 'THREAT_BLOCKED';
  resource: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'SUCCESS' | 'WARNING' | 'FAILED';
  details: string;
}

const AUDIT_DATA: AuditEntry[] = [
  {
    id: 'AUD-9901',
    timestamp: '2026-09-08 04:22:15',
    operator: 'system-agent',
    action: 'RULE_FIRED',
    resource: 'ALT-36CEAA',
    severity: 'critical',
    status: 'SUCCESS',
    details: 'Rule "R-01: Auto-escalate Port 80 short flows" matched payload and applied critical tag.',
  },
  {
    id: 'AUD-9902',
    timestamp: '2026-09-08 04:21:50',
    operator: 'admin@flare.dev',
    action: 'USER_LOGIN',
    resource: 'auth/session',
    severity: 'info',
    status: 'SUCCESS',
    details: 'User authenticated via JWT access token from IP 127.0.0.1.',
  },
  {
    id: 'AUD-9903',
    timestamp: '2026-09-08 04:19:30',
    operator: 'playbook-worker',
    action: 'PLAYBOOK_TRIGGERED',
    resource: 'PB-04: C2 Containment',
    severity: 'high',
    status: 'SUCCESS',
    details: 'Executed playbook action: Firewall rule added to drop traffic from 172.16.0.1.',
  },
  {
    id: 'AUD-9904',
    timestamp: '2026-09-08 04:18:12',
    operator: 'admin@flare.dev',
    action: 'SEVERITY_OVERRIDE',
    resource: 'ALT-285927',
    severity: 'medium',
    status: 'SUCCESS',
    details: 'Analyst manual override from Low to Medium following MITRE T1110 credential check.',
  },
  {
    id: 'AUD-9905',
    timestamp: '2026-09-08 04:15:40',
    operator: 'rules-engine',
    action: 'THREAT_BLOCKED',
    resource: '192.168.10.50:80',
    severity: 'critical',
    status: 'SUCCESS',
    details: 'Incoming SynFlood rate exceeded 1000 pps, automated SYN proxy initiated.',
  },
  {
    id: 'AUD-9906',
    timestamp: '2026-09-08 04:11:22',
    operator: 'system-agent',
    action: 'RULE_FIRED',
    resource: 'ALT-110294',
    severity: 'high',
    status: 'SUCCESS',
    details: 'Rule "R-03: Web Shell Payload Heuristic" triggered on URI /shell.php.',
  },
  {
    id: 'AUD-9907',
    timestamp: '2026-09-08 04:08:05',
    operator: 'admin@flare.dev',
    action: 'SEVERITY_OVERRIDE',
    resource: 'ALT-883192',
    severity: 'low',
    status: 'SUCCESS',
    details: 'Marked internal Nessus scanner IP 10.0.0.5 as false positive authorized scan.',
  },
];

export function AuditLogsPanel() {
  const [search, setSearch] = useState('');
  const [selectedAction, setSelectedAction] = useState<string>('ALL');
  const [activeEntry, setActiveEntry] = useState<AuditEntry | null>(null);

  const filtered = useMemo(() => {
    return AUDIT_DATA.filter((item) => {
      const matchAction = selectedAction === 'ALL' || item.action === selectedAction;
      const matchSearch =
        !search ||
        item.id.toLowerCase().includes(search.toLowerCase()) ||
        item.operator.toLowerCase().includes(search.toLowerCase()) ||
        item.resource.toLowerCase().includes(search.toLowerCase()) ||
        item.details.toLowerCase().includes(search.toLowerCase());
      return matchAction && matchSearch;
    });
  }, [search, selectedAction]);

  return (
    <div className="space-y-4">
      {/* Detail Modal */}
      {activeEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-2xl relative font-mono text-xs">
            <button
              onClick={() => setActiveEntry(null)}
              className="absolute top-4 right-4 text-dim hover:text-ink cursor-pointer"
            >
              <X size={16} />
            </button>
            <div className="flex items-center gap-2">
              <ShieldCheck className="text-blue-400" size={18} />
              <h3 className="font-bold text-sm text-ink uppercase tracking-wider">Audit Log Inspector</h3>
            </div>
            <div className="space-y-2 pt-2 border-t border-edge/60">
              <div className="flex justify-between py-1 border-b border-edge/30">
                <span className="text-dim">Event ID:</span>
                <span className="text-ink font-bold">{activeEntry.id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-edge/30">
                <span className="text-dim">Timestamp:</span>
                <span className="text-ink">{activeEntry.timestamp}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-edge/30">
                <span className="text-dim">Operator / Principal:</span>
                <span className="text-blue-400 font-bold">{activeEntry.operator}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-edge/30">
                <span className="text-dim">Action Type:</span>
                <span className="text-amber-400 font-bold">{activeEntry.action}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-edge/30">
                <span className="text-dim">Target Resource:</span>
                <span className="text-ink">{activeEntry.resource}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-edge/30">
                <span className="text-dim">Execution Status:</span>
                <span className="text-emerald-400 font-bold">{activeEntry.status}</span>
              </div>
              <div className="pt-2">
                <span className="text-dim block mb-1">Detailed Log Message:</span>
                <div className="p-3 bg-void/80 rounded border border-edge text-slate-300 leading-relaxed">
                  {activeEntry.details}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <ScrollText className="text-blue-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              SOC Operation & Incident Audit Logs
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 font-bold">
              Append-Only Tamper Evident
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Cryptographically signed record of triage verdicts, playbook execution commands, analyst overrides, and logins.
          </p>
        </div>

        <button
          onClick={() => alert('Exporting signed audit ledger (JSON-L)...')}
          className="font-mono text-[11px] font-bold px-3 py-1.5 rounded-md bg-raised border border-edge text-ink hover:border-edge-bright transition-all flex items-center gap-1.5 cursor-pointer shadow-sm"
        >
          <Download size={13} />
          <span>Export Ledger</span>
        </button>
      </div>

      {/* Filters Bar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={14} className="absolute left-3 top-2.5 text-dim" />
          <input
            type="text"
            placeholder="Search by ID, operator, IP, or message..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-void/60 border border-edge/80 rounded-md font-mono text-xs text-ink placeholder:text-dim focus:outline-none focus:border-edge-bright"
          />
        </div>

        <div className="flex items-center gap-1.5 font-mono text-[10px] flex-wrap">
          {['ALL', 'RULE_FIRED', 'PLAYBOOK_TRIGGERED', 'SEVERITY_OVERRIDE', 'USER_LOGIN', 'THREAT_BLOCKED'].map((act) => (
            <button
              key={act}
              onClick={() => setSelectedAction(act)}
              className={`px-2.5 py-1 rounded transition-all cursor-pointer ${
                selectedAction === act
                  ? 'bg-blue-500/20 text-blue-300 border border-blue-500/50 font-semibold shadow-sm'
                  : 'text-dim hover:text-ink hover:bg-raised/40'
              }`}
            >
              {act}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <Card3D intensity={3} glare={true} className="w-full">
        <div className="glass-panel-3d rounded-md overflow-hidden border border-edge/80">
          <div className="grid grid-cols-[110px_160px_140px_160px_1fr_60px] gap-2 px-4 py-2.5 border-b border-edge font-mono text-[9px] uppercase tracking-wider text-dim bg-void/40">
            <span>Audit ID</span>
            <span>Timestamp</span>
            <span>Operator</span>
            <span>Action</span>
            <span>Resource & Details</span>
            <span className="text-right">Action</span>
          </div>

          <div className="divide-y divide-edge/40 font-mono text-xs">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-dim">No audit records match the current criteria.</div>
            ) : (
              filtered.map((entry) => (
                <div
                  key={entry.id}
                  className="grid grid-cols-[110px_160px_140px_160px_1fr_60px] gap-2 px-4 py-3 items-center hover:bg-slate-800/30 transition-colors"
                >
                  <span className="font-bold text-ink">{entry.id}</span>
                  <span className="text-dim text-[11px] tabular-nums">{entry.timestamp}</span>
                  <span className="text-blue-400 text-[11px] truncate">{entry.operator}</span>
                  <div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-raised border border-edge text-slate-300 font-semibold">
                      {entry.action}
                    </span>
                  </div>
                  <div className="truncate pr-2">
                    <strong className="text-ink mr-2">{entry.resource}</strong>
                    <span className="text-dim text-[11px]">{entry.details}</span>
                  </div>
                  <div className="text-right">
                    <button
                      onClick={() => setActiveEntry(entry)}
                      className="p-1 rounded text-dim hover:text-ink hover:bg-raised/60 transition-colors cursor-pointer"
                      title="Inspect Log Entry"
                    >
                      <Eye size={13} />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </Card3D>
    </div>
  );
}
