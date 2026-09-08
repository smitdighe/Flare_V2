import { motion } from 'motion/react';
import Icon from './Icon.jsx';
import StatusDot, { toneText } from './StatusDot.jsx';

const SEVERITY_LABELS = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
  unknown: 'UNKNOWN',
};

const SEVERITY_THEME = {
  critical: {
    row: 'bg-red-500/[0.06] border-l-[4px] border-l-red-500 hover:bg-red-500/[0.12]',
    selected: 'bg-red-500/[0.18] border-l-[4px] border-l-red-500 shadow-[inset_0_0_24px_rgba(239,68,68,0.25),0_0_20px_rgba(239,68,68,0.2)]',
    badge: 'border-red-500/40 bg-red-500/20 text-red-400 shadow-[0_0_12px_rgba(239,68,68,0.2)]',
    dot: 'bg-red-500 animate-pulse shadow-[0_0_8px_#ef4444]',
    vector: 'text-red-400',
  },
  high: {
    row: 'bg-amber-500/[0.05] border-l-[4px] border-l-amber-500 hover:bg-amber-500/[0.10]',
    selected: 'bg-amber-500/[0.16] border-l-[4px] border-l-amber-500 shadow-[inset_0_0_24px_rgba(245,158,11,0.25),0_0_20px_rgba(245,158,11,0.2)]',
    badge: 'border-amber-500/40 bg-amber-500/20 text-amber-400 shadow-[0_0_12px_rgba(245,158,11,0.2)]',
    dot: 'bg-amber-500 shadow-[0_0_8px_#f59e0b]',
    vector: 'text-amber-400',
  },
  medium: {
    row: 'bg-yellow-500/[0.04] border-l-[4px] border-l-yellow-400 hover:bg-yellow-500/[0.09]',
    selected: 'bg-yellow-500/[0.15] border-l-[4px] border-l-yellow-400 shadow-[inset_0_0_24px_rgba(250,204,21,0.25),0_0_20px_rgba(250,204,21,0.2)]',
    badge: 'border-yellow-400/40 bg-yellow-400/20 text-yellow-300 shadow-[0_0_12px_rgba(250,204,21,0.2)]',
    dot: 'bg-yellow-400 shadow-[0_0_8px_#facc15]',
    vector: 'text-yellow-300',
  },
  low: {
    row: 'bg-zinc-400/[0.035] border-l-[4px] border-l-zinc-400 hover:bg-zinc-400/[0.08]',
    selected: 'bg-zinc-400/[0.14] border-l-[4px] border-l-zinc-400 shadow-[inset_0_0_24px_rgba(161,161,170,0.25),0_0_20px_rgba(161,161,170,0.2)]',
    badge: 'border-zinc-400/40 bg-zinc-400/20 text-zinc-300 shadow-[0_0_12px_rgba(161,161,170,0.2)]',
    dot: 'bg-zinc-400 shadow-[0_0_8px_#a1a1aa]',
    vector: 'text-zinc-300',
  },
  info: {
    row: 'bg-indigo-500/[0.035] border-l-[4px] border-l-indigo-400 hover:bg-indigo-500/[0.08]',
    selected: 'bg-indigo-500/[0.14] border-l-[4px] border-l-indigo-400 shadow-[inset_0_0_24px_rgba(129,140,248,0.25),0_0_20px_rgba(129,140,248,0.2)]',
    badge: 'border-indigo-400/40 bg-indigo-400/20 text-indigo-300 shadow-[0_0_12px_rgba(129,140,248,0.2)]',
    dot: 'bg-indigo-400 shadow-[0_0_8px_#818cf8]',
    vector: 'text-indigo-300',
  },
};

function formatTime(timestamp) {
  const date = new Date(timestamp);
  return new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(date);
}

function formatRelativeTime(timestamp) {
  const diff = Math.max(0, Date.now() - new Date(timestamp).getTime());
  if (diff < 60_000) return `${Math.max(1, Math.round(diff / 1000))}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  return `${Math.round(diff / 3_600_000)}h ago`;
}

function StageSignal({ alert }) {
  const stages = [
    { key: 'classify', complete: Boolean(alert.severity) },
    { key: 'enrich', complete: Boolean(alert.ioc_checked) },
    { key: 'reason', complete: Boolean(alert.explanation) },
  ];

  return (
    <div className="flex items-center gap-1.5" aria-label="Pipeline stage completion">
      {stages.map((stage, index) => (
        <span
          key={stage.key}
          className={`h-1.5 w-1.5 rounded-full transition-all ${
            stage.complete
              ? 'bg-white shadow-[0_0_6px_rgba(255,255,255,0.4)]'
              : 'bg-white/15'
          }`}
          title={`${stage.key}: ${stage.complete ? 'complete' : 'pending'}`}
        />
      ))}
    </div>
  );
}

function EmptyState({ query, onClear }) {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center border-t border-white/[0.06] px-6 text-center">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.02] text-muted-foreground">
        <Icon name="search_off" size={18} />
      </div>
      <p className="font-mono text-sm font-medium text-foreground">{query ? 'NO MATCHING SIGNALS' : 'NO SIGNALS IN BUFFER'}</p>
      <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-muted-foreground">{query ? 'Try a different query or clear the active filters.' : 'New alerts will appear here when the stream is active.'}</p>
      {query && <button type="button" className="mt-4 font-mono text-[10px] uppercase tracking-[0.12em] text-white underline decoration-white/40 underline-offset-4 hover:text-foreground" onClick={onClear}>Clear filters</button>}
    </div>
  );
}

export default function AlertTable({ alerts, selected, onSelect, activeIndex = -1, isLoading = false, query = '', onClear, density = 'comfortable' }) {
  const rowPadding = density === 'compact' ? 'py-2.5' : 'py-3.5';

  if (isLoading) {
    return (
      <div className="space-y-1.5 border-t border-white/[0.06] p-6" aria-label="Loading alerts">
        {Array.from({ length: 5 }, (_, index) => <div key={index} className="h-12 rounded-xl bg-white/[0.03] animate-pulse" />)}
      </div>
    );
  }

  if (alerts.length === 0) return <EmptyState query={query} onClear={onClear} />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[800px] border-collapse text-left">
        <caption className="sr-only">Live security alerts</caption>
        <thead>
          <tr className="border-b border-white/[0.06] bg-white/[0.015] font-sans text-xs font-semibold uppercase tracking-wider text-zinc-400">
            <th scope="col" className="w-[14%] px-6 py-3.5 font-medium">Signal / age</th>
            <th scope="col" className="w-[12%] px-3 py-3.5 font-medium">Severity</th>
            <th scope="col" className="w-[15%] px-3 py-3.5 font-medium">Vector</th>
            <th scope="col" className="w-[26%] px-3 py-3.5 font-medium">Route</th>
            <th scope="col" className="w-[18%] px-3 py-3.5 font-medium">Signature</th>
            <th scope="col" className="w-[10%] px-3 py-3.5 font-medium">Pipeline</th>
            <th scope="col" className="w-[5%] px-6 py-3.5 text-right font-medium"><span className="sr-only">Open</span></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {alerts.map((alert, index) => {
            const isSelected = selected?.id === alert.id;
            const isActive = activeIndex === index;
            const theme = SEVERITY_THEME[alert.severity] || SEVERITY_THEME.low;
            return (
              <motion.tr
                key={`${alert.id}-${index}`}
                className={`group transition-all duration-200 cursor-pointer ${
                  isSelected
                    ? theme.selected
                    : isActive
                    ? `${theme.row} brightness-125`
                    : theme.row
                }`}
                initial={{ opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(index, 7) * 0.035, duration: 0.28 }}
                data-selected={isSelected}
                aria-selected={isSelected}
                onClick={() => onSelect(alert)}
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    onSelect(alert);
                  }
                }}
              >
                <td className={`px-6 ${rowPadding} align-top`}>
                  <div className="flex items-start gap-2.5">
                    <StatusDot tone={alert.severity} pulse={alert.severity === 'critical' || alert.severity === 'high'} />
                    <div>
                      <div className="font-mono text-xs font-semibold text-white">{formatTime(alert.timestamp)}</div>
                      <div className="mt-0.5 font-sans text-[11px] text-zinc-400">{formatRelativeTime(alert.timestamp)}</div>
                    </div>
                  </div>
                </td>
                <td className={`px-3 ${rowPadding} align-top`}>
                  <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-sans text-[10px] font-semibold tracking-wide capitalize ${theme.badge}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${theme.dot}`} />
                    {SEVERITY_LABELS[alert.severity] || 'UNKNOWN'}
                  </span>
                </td>
                <td className={`px-3 ${rowPadding} align-top`}>
                  <div className={`font-sans text-xs font-semibold capitalize ${theme.vector}`}>
                    {alert.attack_type?.replaceAll('_', ' ')}
                  </div>
                  <div className="mt-0.5 font-mono text-[10px] text-zinc-400">{alert.protocol}:{alert.dest_port}</div>
                </td>
                <td className={`px-3 ${rowPadding} align-top`}>
                  <div className="flex items-center gap-2 font-mono text-xs text-white">
                    <span>{alert.src_ip}</span>
                    <span className="text-zinc-500">→</span>
                    <span>{alert.dest_ip}</span>
                  </div>
                  <div className="mt-0.5 font-sans text-[11px] text-zinc-400">MITRE {alert.mitre_technique || '—'}</div>
                </td>
                <td className={`max-w-0 px-3 ${rowPadding} align-top`}>
                  <div className="truncate font-sans text-xs font-medium text-zinc-200" title={alert.signature}>{alert.signature}</div>
                  <div className="mt-0.5 truncate font-mono text-[10px] text-zinc-400">{alert.id}</div>
                </td>
                <td className={`px-3 ${rowPadding} align-middle`}><StageSignal alert={alert} /></td>
                <td className={`px-6 ${rowPadding} text-right align-top`}>
                  <div className="flex justify-end">
                    <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-transparent transition-all group-hover:border-white/10 group-hover:bg-white/[0.06] group-hover:text-white">
                      <Icon name="arrow_forward" size={15} />
                    </span>
                  </div>
                </td>
              </motion.tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export { formatTime, formatRelativeTime };
