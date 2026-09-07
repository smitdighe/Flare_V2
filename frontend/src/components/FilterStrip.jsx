import { useEffect, useState } from 'react';
import Icon from './Icon.jsx';

const API_BASE = import.meta.env.VITE_API_BASE || '';

const SEVERITY_OPTIONS = [
  { value: '', label: 'ALL SIGNALS' },
  { value: 'high', label: 'HIGH' },
  { value: 'medium', label: 'MEDIUM' },
  { value: 'low', label: 'LOW' },
];

export { SEVERITY_OPTIONS };

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
    <div className="border-b border-line-strong bg-ink-850/50 px-4 py-3">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Severity filters">
          {SEVERITY_OPTIONS.map((option) => (
            <button
              type="button"
              key={option.value || 'all'}
              className={`filter-chip border px-2 py-1.5 font-mono-ui text-[9px] uppercase tracking-[0.08em] transition-colors ${filters.severity === option.value || (!filters.severity && !option.value) ? 'border-amber bg-amber text-ink-950' : 'border-line-strong bg-ink-900 text-ash hover:border-ash-dark hover:text-paper'}`}
              onClick={() => onFilterChange({ severity: option.value || undefined })}
              aria-pressed={filters.severity === option.value || (!filters.severity && !option.value)}
            >
              {option.value && <span className="mr-1">[ ]</span>}
              {option.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 border border-line-strong bg-ink-900 px-2 py-1.5">
            <span className="font-mono-ui text-[9px] uppercase tracking-[0.08em] text-ash-dark">VECTOR</span>
            <select
              value={filters.attack_type || ''}
              onChange={(event) => onFilterChange({ attack_type: event.target.value || undefined })}
              className="bg-transparent font-mono-ui text-[10px] text-paper outline-hidden"
            >
              <option value="">ALL TYPES</option>
              {attackTypes.map((type) => (
                <option key={type.value} value={type.value}>{type.label}</option>
              ))}
            </select>
          </label>
          <span className="font-mono-ui text-[9px] uppercase tracking-[0.08em] text-ash-dark">{resultCount} visible</span>
          {isFiltered && (
            <button
              type="button"
              className="font-mono-ui text-[9px] uppercase tracking-[0.08em] text-yellow underline decoration-yellow/50 underline-offset-4"
              onClick={onClear}
            >
              CLEAR FILTERS
            </button>
          )}
          <button
            type="button"
            className="ghost-button inline-flex items-center gap-1 border border-line-strong px-2 py-1.5 font-mono-ui text-[9px] uppercase tracking-[0.08em] text-ash hover:border-amber hover:text-amber"
            onClick={onAddAlert}
          >
            <Icon name="add" size={13} />
            <span>RELOAD</span>
          </button>
        </div>
      </div>
    </div>
  );
}
