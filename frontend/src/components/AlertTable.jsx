import { motion } from 'motion/react';
import Icon from './Icon.jsx';
import StatusDot, { toneText } from './StatusDot.jsx';

const SEVERITY_LABELS = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  unknown: 'UNKNOWN',
};

const SEVERITY_BADGE = {
  critical: 'border-red-500/50 text-red-400',
  high: 'border-amber/50 text-amber',
  medium: 'border-yellow/50 text-yellow',
  low: 'border-line-strong text-ash',
  unknown: 'border-line-strong text-ash',
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
    <div className="stage-signal" aria-label="Pipeline stage completion">
      {stages.map((stage, index) => (
        <span key={stage.key} className={`h-2 w-2 border ${stage.complete ? 'border-amber bg-amber' : 'border-line-strong bg-transparent'}`} style={{ '--stage-index': index }} title={`${stage.key}: ${stage.complete ? 'complete' : 'pending'}`} />
      ))}
    </div>
  );
}

function EmptyState({ query, onClear }) {
  return (
    <div className="flex min-h-[300px] flex-col items-center justify-center border-t border-line px-6 text-center">
      <div className="mb-3 flex h-10 w-10 items-center justify-center border border-line-strong text-ash-dark">
        <Icon name="search_off" size={20} />
      </div>
      <p className="font-mono-ui text-sm text-paper">{query ? 'NO MATCHING SIGNALS' : 'NO SIGNALS IN BUFFER'}</p>
      <p className="mt-2 max-w-sm text-xs leading-5 text-ash">{query ? 'Try a different query or clear the active filters.' : 'New alerts will appear here when the stream is active.'}</p>
      {query && <button type="button" className="mt-4 font-mono-ui text-[10px] uppercase tracking-[0.12em] text-amber underline decoration-amber/40 underline-offset-4" onClick={onClear}>Clear filters</button>}
    </div>
  );
}

export default function AlertTable({ alerts, selected, onSelect, activeIndex = -1, isLoading = false, query = '', onClear, density = 'comfortable' }) {
  const rowPadding = density === 'compact' ? 'py-2' : 'py-3';

  if (isLoading) {
    return (
      <div className="space-y-px border-t border-line p-3" aria-label="Loading alerts">
        {Array.from({ length: 5 }, (_, index) => <div key={index} className="loading-bar h-12" />)}
      </div>
    );
  }

  if (alerts.length === 0) return <EmptyState query={query} onClear={onClear} />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-left">
        <caption className="sr-only">Live security alerts</caption>
        <thead>
          <tr className="font-mono-ui text-[9px] uppercase tracking-[0.12em] text-ash-dark">
            <th scope="col" className="w-[14%] px-4 py-3 font-medium">Signal / age</th>
            <th scope="col" className="w-[11%] px-2 py-3 font-medium">Severity</th>
            <th scope="col" className="w-[15%] px-2 py-3 font-medium">Vector</th>
            <th scope="col" className="w-[28%] px-2 py-3 font-medium">Route</th>
            <th scope="col" className="w-[17%] px-2 py-3 font-medium">Signature</th>
            <th scope="col" className="w-[10%] px-2 py-3 font-medium">Pipeline</th>
            <th scope="col" className="w-[5%] px-4 py-3 text-right font-medium"><span className="sr-only">Open</span></th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => {
            const isSelected = selected?.id === alert.id;
            const isActive = activeIndex === index;
            return (
              <motion.tr
                key={alert.id}
                className={`data-row alert-enter group font-mono-ui text-[11px] ${isActive ? 'outline outline-1 outline-amber/70 -outline-offset-1' : ''}`}
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(index, 7) * 0.045, duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
                style={{ '--row-delay': `${Math.min(index, 7) * 45}ms` }}
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
                <td className={`px-4 ${rowPadding} align-top`}>
                  <div className="flex items-start gap-2">
                    <StatusDot tone={alert.severity} pulse={alert.severity === 'high'} />
                    <div>
                      <div className="text-paper">{formatTime(alert.timestamp)}</div>
                      <div className="mt-1 text-[10px] text-ash-dark">{formatRelativeTime(alert.timestamp)}</div>
                    </div>
                  </div>
                </td>
                <td className={`px-2 ${rowPadding} align-top`}>
                  <span className={`inline-flex border px-1.5 py-0.5 text-[9px] font-semibold tracking-[0.08em] ${SEVERITY_BADGE[alert.severity] || SEVERITY_BADGE.low}`}>
                    {SEVERITY_LABELS[alert.severity] || 'UNKNOWN'}
                  </span>
                </td>
                <td className={`px-2 ${rowPadding} align-top`}>
                  <span className={`font-semibold ${toneText(alert.severity)}`}>{alert.attack_type?.replaceAll('_', ' ')}</span>
                  <span className="mt-1 block text-[10px] text-ash-dark">{alert.protocol}:{alert.dest_port}</span>
                </td>
                <td className={`px-2 ${rowPadding} align-top`}>
                  <div className="flex items-center gap-2 text-paper">
                    <span>{alert.src_ip}</span><span className="text-ash-dark">→</span><span>{alert.dest_ip}</span>
                  </div>
                  <div className="mt-1 text-[10px] text-ash-dark">MITRE {alert.mitre_technique || '—'}</div>
                </td>
                <td className={`max-w-0 px-2 ${rowPadding} align-top`}>
                  <div className="truncate text-ash" title={alert.signature}>{alert.signature}</div>
                  <div className="mt-1 truncate text-[10px] text-ash-dark">{alert.id}</div>
                </td>
                <td className={`px-2 ${rowPadding} align-top`}><StageSignal alert={alert} /></td>
                <td className={`px-4 ${rowPadding} text-right align-top`}>
                  <button type="button" className="text-ash-dark transition-colors group-hover:text-amber" aria-label={`Open ${alert.id}`} onClick={(event) => { event.stopPropagation(); onSelect(alert); }}>
                    <Icon name="arrow_forward" size={16} />
                  </button>
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
