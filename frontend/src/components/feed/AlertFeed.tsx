import { useEffect, useMemo, useRef, useState } from 'react';
import type { AlertSummary, Severity } from '@/types';
import {
  SEVERITY_FLASH_ANIM,
  SEVERITY_HEX_CLASS,
  SEVERITY_TEXT,
  STATUS_LABELS,
} from '@/types';
import { Card3D } from '@/components/ui/Card3D';
import { Zap, RotateCcw } from 'lucide-react';
import { InjectAlertModal } from '@/components/feed/InjectAlertModal';
import { seedAlerts, generateAlertDetail } from '@/lib/generator';

interface AlertFeedProps {
  alerts: AlertSummary[];
  onSelect: (alert: AlertSummary) => void;
  selectedId?: string;
  filters: FeedFilters;
  onFiltersChange: (f: FeedFilters) => void;
  onInjectCustomAlert?: (body: { signature: string; src_ip: string; dst_ip: string; dst_port?: number; protocol?: string }) => void;
}

export interface FeedFilters {
  severities: Set<Severity>;
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_BAR: Record<Severity, string> = {
  critical: 'bg-[#d00000] shadow-[0_0_10px_#d00000]',
  high: 'bg-[#CC5500] shadow-[0_0_10px_#CC5500]',
  medium: 'bg-[#E49B0F] shadow-[0_0_10px_#E49B0F]',
  low: 'bg-[#E5B75D] shadow-[0_0_10px_#E5B75D]',
  info: 'bg-[#71717a] shadow-[0_0_10px_#71717a]',
};

const SEV_ROW_CLASS: Record<Severity, string> = {
  critical: 'sev-row-critical',
  high: 'sev-row-high',
  medium: 'sev-row-medium',
  low: 'sev-row-low',
  info: 'sev-row-unknown',
};

export function AlertFeed({ alerts, onSelect, selectedId, filters, onFiltersChange, onInjectCustomAlert }: AlertFeedProps) {
  const [internalAlerts, setInternalAlerts] = useState<AlertSummary[]>(() => {
    if (alerts && alerts.length > 0) return alerts;
    return seedAlerts(25);
  });
  const [seenIds, setSeenIds] = useState<Set<string>>(new Set());
  const [injectOpen, setInjectOpen] = useState(false);
  const prevIdsRef = useRef<Set<string>>(new Set());

  // Sync incoming alerts prop into internal stream
  useEffect(() => {
    if (alerts && alerts.length > 0) {
      setInternalAlerts((prev) => {
        const map = new Map<string, AlertSummary>();
        alerts.forEach((a) => map.set(a.id, a));
        prev.forEach((a) => {
          if (!map.has(a.id)) map.set(a.id, a);
        });
        return Array.from(map.values()).slice(0, 150);
      });
    }
  }, [alerts]);

  // Real-time live threat telemetry pulse
  useEffect(() => {
    const timer = setInterval(() => {
      const freshAlert = generateAlertDetail();
      setSeenIds((prev) => new Set([...prev, freshAlert.id]));
      setInternalAlerts((prev) => [freshAlert, ...prev.filter((a) => a.id !== freshAlert.id)].slice(0, 150));
    }, 2200);

    return () => clearInterval(timer);
  }, []);

  // Track fresh IDs for entrance flash animation
  useEffect(() => {
    const currentIds = new Set(internalAlerts.map((a) => a.id));
    const fresh = new Set<string>();
    for (const id of currentIds) {
      if (!prevIdsRef.current.has(id)) fresh.add(id);
    }
    if (fresh.size > 0) {
      setSeenIds((prev) => {
        const merged = new Set([...prev, ...fresh]);
        if (merged.size <= 200) return merged;
        return new Set([...merged].slice(-150));
      });
    }
    prevIdsRef.current = currentIds;
  }, [internalAlerts]);

  const filtered = useMemo(() => {
    const activeList = internalAlerts.length > 0 ? internalAlerts : alerts;
    if (!activeList || !Array.isArray(activeList)) return [];
    return activeList.filter((a) => {
      const rawSev = String(a.severity || 'info').toLowerCase();
      const s: Severity = (['critical', 'high', 'medium', 'low', 'info'].includes(rawSev)
        ? rawSev
        : 'info') as Severity;
      return filters.severities.has(s);
    });
  }, [internalAlerts, alerts, filters]);

  const toggleSev = (sev: Severity) => {
    const next = new Set(filters.severities);
    if (next.has(sev)) next.delete(sev);
    else next.add(sev);
    if (next.size === 0) {
      onFiltersChange({ severities: new Set(SEV_ORDER) });
    } else {
      onFiltersChange({ severities: next });
    }
  };

  const resetFilters = () => {
    onFiltersChange({ severities: new Set(SEV_ORDER) });
  };

  return (
    <Card3D intensity={4} glare={true} className="w-full h-full">
      <div className="flex flex-col h-full glass-panel-3d rounded-md overflow-hidden shadow-2xl border border-edge/80 metal-bevel">
        {/* Modal for Custom Inject Alert */}
        <InjectAlertModal
          isOpen={injectOpen}
          onClose={() => setInjectOpen(false)}
          onInjectCustomAlert={(custom) => {
            const manualAlert = generateAlertDetail();
            manualAlert.signature = custom.signature;
            manualAlert.src_ip = custom.src_ip;
            manualAlert.dst_ip = custom.dst_ip;
            if (custom.dst_port) manualAlert.dst_port = custom.dst_port;
            if (custom.protocol) manualAlert.protocol = custom.protocol;
            manualAlert.severity = 'critical';
            setSeenIds((prev) => new Set([...prev, manualAlert.id]));
            setInternalAlerts((prev) => [manualAlert, ...prev]);
            if (onInjectCustomAlert) onInjectCustomAlert(custom);
          }}
        />

        {/* header / filter chips */}
        <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-edge/80 bg-slate-900/30 backdrop-blur-md flex-wrap">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-[#E5B75D] animate-pulse-soft shadow-[0_0_8px_#E5B75D]" />
            <h2 className="font-mono text-xs font-semibold tracking-[0.16em] text-ink uppercase">
              Live Threat Telemetry Stream
            </h2>
            <span className="font-mono text-[10px] px-2 py-0.5 bg-raised/80 text-dim border border-edge/80 rounded-md font-medium shadow-inner">
              {filtered.length} active alerts
            </span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setInjectOpen(true)}
              className="font-mono text-[10px] px-3 py-1 bg-red-500/15 border border-red-500/40 text-red-400 hover:bg-red-500/25 rounded-md transition-all font-bold cursor-pointer flex items-center gap-1.5 shadow-[0_0_12px_rgba(208,0,0,0.25)]"
            >
              <Zap size={11} className="text-red-400" />
              <span>Inject Alert</span>
            </button>

            <div className="flex items-center gap-1.5">
              {SEV_ORDER.map((sev) => {
                const active = filters.severities.has(sev);
                return (
                  <button
                    key={sev}
                    onClick={() => toggleSev(sev)}
                    aria-pressed={active}
                    className={`font-mono text-[10px] uppercase tracking-wider px-2.5 py-1 border rounded-md transition-all duration-200 cursor-pointer ${
                      active
                        ? 'border-edge-bright text-ink bg-raised/90 shadow-md font-semibold translate-z-1'
                        : 'border-transparent text-dim hover:text-ink hover:bg-raised/40'
                    }`}
                  >
                    <span className={`inline-block h-1.5 w-1.5 rounded-full mr-1.5 align-middle ${SEV_BAR[sev]}`} />
                    {SEVERITY_TEXT[sev]}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* column headers */}
        <div className="grid grid-cols-[130px_90px_1fr_140px_120px_90px] gap-2 px-4 py-2 border-b border-edge/80 font-mono text-[9px] uppercase tracking-[0.14em] text-dim bg-slate-900/40 backdrop-blur-md shadow-inner">
          <span>Timestamp</span>
          <span>Severity</span>
          <span>Attack Vector / IP flow</span>
          <span className="hidden lg:block">IOC Score</span>
          <span className="hidden md:block">Pipeline Status</span>
          <span className="text-right">Confidence</span>
        </div>

        {/* rows */}
        <div className="flex-1 overflow-y-auto divide-y divide-edge/40">
          {filtered.length === 0 ? (
            <div className="px-4 py-16 text-center space-y-3">
              <p className="font-mono text-xs text-dim">
                No alerts matching active filter — toggle a severity chip above.
              </p>
              <button
                onClick={resetFilters}
                className="font-mono text-[11px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-md border border-edge transition-colors inline-flex items-center gap-1.5 cursor-pointer"
              >
                <RotateCcw size={12} />
                <span>Show All Alerts ({internalAlerts.length})</span>
              </button>
            </div>
          ) : (
            filtered.map((alert) => {
              const isFresh = seenIds.has(alert.id);
              const isSelected = selectedId === alert.id;
              const confPct = alert.confidence !== null ? Math.round(alert.confidence * 100) : 0;
              const rawSev = String(alert.severity || 'info').toLowerCase();
              const severityKey: Severity = (['critical', 'high', 'medium', 'low', 'info'].includes(rawSev)
                ? rawSev
                : 'info') as Severity;

              const isEscalated = (alert.max_ioc_score ?? 0) >= 80 && severityKey === 'high';

              return (
                <button
                  key={alert.id}
                  onClick={() => onSelect(alert)}
                  className={`relative w-full text-left grid grid-cols-[130px_90px_1fr_140px_120px_90px] gap-2 px-4 py-3 transition-all duration-200 group cursor-pointer backdrop-blur-sm ${
                    SEV_ROW_CLASS[severityKey]
                  } ${
                    isSelected
                      ? 'ring-1 ring-white/20 shadow-[inset_0_0_24px_rgba(255,255,255,0.06)]'
                      : ''
                  } ${isFresh ? 'animate-row-enter' : ''}`}
                >
                  {/* flash overlay */}
                  {isFresh && (
                    <span
                      className={`absolute left-0 top-0 bottom-0 right-0 ${SEV_BAR[severityKey]} ${SEVERITY_FLASH_ANIM[severityKey]} pointer-events-none opacity-30`}
                      aria-hidden
                      onAnimationEnd={() =>
                        setSeenIds((prev) => {
                          const n = new Set(prev);
                          n.delete(alert.id);
                          return n;
                        })
                      }
                    />
                  )}

                  {/* Timestamp */}
                  <span className="font-mono text-[10px] text-dim tabular-nums truncate my-auto">
                    {alert.timestamp.includes('T') ? alert.timestamp.split('T')[1].replace('Z', '') : alert.timestamp}
                  </span>

                  {/* Severity */}
                  <div className="my-auto flex items-center gap-1.5">
                    <span className={`inline-block h-1.5 w-1.5 rounded-full ${SEV_BAR[severityKey]}`} />
                    {alert.severity ? (
                      <span className={`sev-progress-badge ${SEVERITY_HEX_CLASS[alert.severity]}`}>
                        {SEVERITY_TEXT[alert.severity]}
                      </span>
                    ) : (
                      <span className="font-mono text-[10px] text-dim animate-pulse">CLASSIFYING...</span>
                    )}
                  </div>

                  {/* Attack Type & IP Flow */}
                  <span className="min-w-0 my-auto">
                    <span className="block text-[13px] text-ink truncate font-semibold group-hover:text-white transition-colors">
                      {alert.attack_type || alert.signature}
                    </span>
                    <span className="block font-mono text-[10px] text-dim truncate">
                      {alert.src_ip} → {alert.dst_ip}:{alert.dst_port || '80'} / {alert.protocol || 'TCP'}
                    </span>
                  </span>

                  {/* Max IOC Score */}
                  <span className="hidden lg:flex items-center gap-1.5 font-mono text-[11px] my-auto">
                    {alert.max_ioc_score !== null ? (
                      <span
                        className={`px-2 py-0.5 rounded-md text-[10px] font-bold border shadow-inner flex items-center gap-1 ${
                          alert.max_ioc_score >= 80
                            ? 'bg-[#d00000]/15 text-[#ff8080] border-[#d00000]/50 shadow-[0_0_10px_rgba(208,0,0,0.3)]'
                            : alert.max_ioc_score >= 50
                            ? 'bg-[#CC5500]/15 text-[#ffa55c] border-[#CC5500]/40'
                            : 'bg-void text-dim border-edge/60'
                        }`}
                      >
                        {isEscalated && <Zap size={10} className="animate-bounce" />}
                        {alert.max_ioc_score} / 100
                      </span>
                    ) : alert.has_enrichment ? (
                      <span className="text-[10px] text-dim">0 / 100</span>
                    ) : (
                      <span className="text-[10px] text-dim italic">Pending</span>
                    )}
                  </span>

                  {/* Pipeline Status */}
                  <span className="hidden md:flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider my-auto">
                    <span
                      className={`px-1.5 py-0.5 rounded font-semibold text-[9px] border ${
                        alert.status === 'done'
                          ? 'bg-ok/10 text-ok border-ok/30'
                          : alert.status === 'failed'
                          ? 'bg-[#d00000]/10 text-[#ff8080] border-[#d00000]/30'
                          : alert.status === 'reasoned' || alert.status === 'enriched'
                          ? 'bg-[#E5B75D]/10 text-[#f8e4b4] border-[#E5B75D]/30'
                          : 'bg-raised text-dim border-edge/60'
                      }`}
                    >
                      {STATUS_LABELS[alert.status]}
                    </span>
                  </span>

                  {/* AI Confidence Bar */}
                  <div className="flex flex-col items-end justify-center my-auto font-mono">
                    <span className="text-[11px] text-ink font-bold tabular-nums">
                      {confPct > 0 ? `${confPct}%` : '—'}
                    </span>
                    <div className="w-14 h-1.5 bg-void border border-edge/80 rounded-sm overflow-hidden mt-1 shadow-inner">
                      <div
                        className={`h-full transition-all duration-500 rounded-xs shadow-[0_0_6px_currentColor] ${
                          confPct > 80
                            ? 'bg-[#22c55e] text-[#22c55e]'
                            : confPct > 60
                            ? 'bg-[#E49B0F] text-[#E49B0F]'
                            : 'bg-[#d00000] text-[#d00000]'
                        }`}
                        style={{ width: `${confPct}%` }}
                      />
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </Card3D>
  );
}
