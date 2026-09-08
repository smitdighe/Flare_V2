import { useEffect, useState } from 'react';
import Icon from './Icon.jsx';
import CyberSelect from './CyberSelect.jsx';

const API_BASE = import.meta.env.VITE_API_BASE || '';

const SEVERITY_OPTIONS = [
  { value: '', label: 'All signals' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

export { SEVERITY_OPTIONS };

const SEVERITY_BUTTON_STYLES = {
  '': {
    active: 'border-white/30 bg-white/10 text-white shadow-[0_0_14px_rgba(255,255,255,0.14)] font-semibold',
    dot: 'bg-white',
  },
  critical: {
    active: 'border-red-500/50 bg-red-500/20 text-red-400 shadow-[0_0_16px_rgba(239,68,68,0.25)] font-semibold',
    dot: 'bg-red-500 animate-pulse shadow-[0_0_8px_#ef4444]',
  },
  high: {
    active: 'border-amber-500/50 bg-amber-500/20 text-amber-400 shadow-[0_0_16px_rgba(245,158,11,0.25)] font-semibold',
    dot: 'bg-amber-500 shadow-[0_0_8px_#f59e0b]',
  },
  medium: {
    active: 'border-yellow-400/50 bg-yellow-400/20 text-yellow-300 shadow-[0_0_16px_rgba(250,204,21,0.25)] font-semibold',
    dot: 'bg-yellow-400 shadow-[0_0_8px_#facc15]',
  },
  low: {
    active: 'border-zinc-400/50 bg-zinc-400/20 text-zinc-300 shadow-[0_0_16px_rgba(161,161,170,0.25)] font-semibold',
    dot: 'bg-zinc-400 shadow-[0_0_8px_#a1a1aa]',
  },
  info: {
    active: 'border-indigo-400/50 bg-indigo-400/20 text-indigo-300 shadow-[0_0_16px_rgba(129,140,248,0.25)] font-semibold',
    dot: 'bg-indigo-400 shadow-[0_0_8px_#818cf8]',
  },
};

export default function FilterStrip({ filters, onFilterChange, resultCount, density, onDensityChange, onAddAlert, onClear }) {
  const isFiltered = Boolean(filters.search || filters.severity || filters.attack_type);

  // FE-11: the vector options are whatever the data contains. They used to be
  // a hardcoded array in which four of six values matched no alert.
  const [attackTypes, setAttackTypes] = useState([]);

  useEffect(() => {
    let cancelled = false;
    const token = localStorage.getItem('flare_token');
    fetch(`${API_BASE}/api/v1/alerts/attack-types`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((json) => {
        if (cancelled || !json?.ok) return;
        if (Array.isArray(json.data?.attack_types)) setAttackTypes(json.data.attack_types);
      })
      .catch(() => { /* leaves ALL TYPES only — better than offering dead options */ });
    return () => { cancelled = true; };
  }, []);
  return (
    <div className="border-b border-white/[0.06] bg-white/[0.015] px-6 py-3.5">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Severity filters">
          {SEVERITY_OPTIONS.map((option) => {
            const isSelected = filters.severity === option.value || (!filters.severity && !option.value);
            const style = SEVERITY_BUTTON_STYLES[option.value] || SEVERITY_BUTTON_STYLES[''];
            return (
              <button
                type="button"
                key={option.value || 'all'}
                className={`relative inline-flex items-center gap-2 rounded-xl border px-3.5 py-1.5 font-sans text-xs transition-all duration-200 ${
                  isSelected
                    ? style.active
                    : 'border-white/10 bg-white/[0.02] text-zinc-400 hover:border-white/20 hover:bg-white/[0.05] hover:text-white font-medium'
                }`}
                onClick={() => onFilterChange({ severity: option.value || undefined })}
                aria-pressed={isSelected}
              >
                {option.value && (
                  <span className={`h-2 w-2 rounded-full ${style.dot}`} />
                )}
                <span>{option.label}</span>
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <CyberSelect
            prefix="VECTOR"
            value={filters.attack_type || ''}
            onChange={(val) => onFilterChange({ attack_type: val || undefined })}
            options={[
              { value: '', label: 'ALL TYPES' },
              ...attackTypes.map((type) => ({ value: type.value, label: type.label })),
            ]}
          />
          <span className="rounded-xl border border-white/10 bg-white/[0.02] px-3 py-1.5 font-mono text-[11px] text-zinc-400">
            {resultCount} visible
          </span>
          {isFiltered && (
            <button
              type="button"
              className="font-sans text-xs font-medium text-white underline decoration-white/40 underline-offset-4 transition-colors hover:text-white"
              onClick={onClear}
            >
              Clear filters
            </button>
          )}
          <button
            type="button"
            className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.02] px-3.5 py-1.5 font-sans text-xs font-medium text-zinc-400 transition-all hover:border-white/30 hover:bg-white/[0.05] hover:text-white"
            onClick={onAddAlert}
          >
            <Icon name="add" size={14} />
            <span>Reload</span>
          </button>
        </div>
      </div>
    </div>
  );
}
