import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useState, useCallback } from 'react';
import { DashSidebar } from './dash/DashSidebar.jsx';
import { TopBar } from './dash/TopBar.jsx';
import { RightRail } from './dash/RightRail.jsx';
import { CommandPalette } from './dash/CommandPalette.jsx';
import AlertDetailDrawer from './AlertDetailDrawer.jsx';
import WorkspacePanel from './WorkspacePanel.jsx';

const API_BASE = import.meta.env.VITE_API_BASE || '';

// FE-15 (PLAN §3.3). The counters and the ticker used to be computed from the
// 200-alert browser buffer, so TOTAL/HIGH/MEDIUM were wrong the moment the
// dataset outgrew the buffer and wrong again the moment a filter was applied.
// `GET /metrics/overview` counts over the whole alerts table using the same
// predicates as `GET /alerts`, so the header and the table cannot disagree.
function useOverview(filters) {
  const [overview, setOverview] = useState(null);
  const severity = filters?.severity || '';
  const attackType = filters?.attack_type || '';
  const search = filters?.search || '';

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const token = localStorage.getItem('flare_token');
        const params = new URLSearchParams();
        if (severity) params.set('severity', severity);
        if (attackType) params.set('attack_type', attackType);
        if (search) params.set('search', search);
        const query = params.toString();
        const res = await fetch(`${API_BASE}/api/v1/metrics/overview${query ? `?${query}` : ''}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const json = await res.json();
        if (!cancelled) setOverview(json.data || json);
      } catch { /* the counters hold their last real value */ }
    };
    load();
    const id = setInterval(load, 10000);
    return () => { cancelled = true; clearInterval(id); };
  }, [severity, attackType, search]);

  return overview;
}

export default function DashboardView({ alerts, filteredAlerts, selected, onSelect, onClose, filters, onFilterChange, activeSection, onNavigate, paused, onTogglePaused, density, onDensityChange, onAddAlert, onLogout, connectionStatus }) {
  const [commandOpen, setCommandOpen] = useState(false);
  const overview = useOverview(filters);
  const bySeverity = overview?.by_severity;

  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen(true);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleNavigate = useCallback((section) => {
    onNavigate(section);
    setCommandOpen(false);
  }, [onNavigate]);

  return (
    <div id="dashboard" className={`relative min-h-screen bg-black text-foreground ${density === 'compact' ? 'density-compact' : ''}`}>
      {/* Atmospheric Ambient Lighting Mesh for Glassmorphic Refraction */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
        <div className="absolute -top-40 left-1/3 h-[500px] w-[600px] rounded-full bg-primary/10 blur-[150px]" />
        <div className="absolute top-1/3 -right-40 h-[600px] w-[600px] rounded-full bg-sky-600/8 blur-[160px]" />
        <div className="absolute bottom-10 left-10 h-[400px] w-[400px] rounded-full bg-blue-700/5 blur-[140px]" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff04_1px,transparent_1px),linear-gradient(to_bottom,#ffffff04_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-80" />
      </div>

      <TopBar
        ticker={overview?.ticker}
        onCommand={() => setCommandOpen(true)}
        onLogout={onLogout}
        onNavigate={handleNavigate}
        activeSection={activeSection}
      />
      <DashSidebar
        activeSection={activeSection}
        onNavigate={handleNavigate}
      />
      <main className="relative z-10 min-h-[calc(100vh-3.5rem)] pt-14 lg:pl-64">
        <div className="mx-auto max-w-[1440px] px-4 py-6 lg:px-8 lg:py-8">
          <div className="mt-2 mb-8 flex flex-col md:flex-row md:items-end justify-between gap-6">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3.5 py-1 text-[11px] font-sans backdrop-blur-md shadow-[inset_0_1px_1px_rgba(255,255,255,0.08)]">
                <span className={`h-2 w-2 rounded-full ${paused ? 'bg-yellow-400' : 'bg-emerald-400 animate-pulse'}`} />
                <span className={paused ? 'text-yellow-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                  {paused ? 'STREAM PAUSED' : 'STREAM ACTIVE'}
                </span>
                <span className="text-white/20">/</span>
                <span className="text-zinc-400 capitalize">{activeSection}</span>
              </div>
              <h1 className="mt-3 text-3xl md:text-4xl font-bold tracking-tight text-white font-sans flex items-center gap-2">
                {activeSection === 'settings' ? (
                  <>System console <span className="text-zinc-500 font-normal">/ configuration</span></>
                ) : (
                  <>Incident command <span className="text-zinc-500 font-normal">/ live queue</span></>
                )}
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-zinc-400 font-sans">
                {activeSection === 'settings'
                  ? 'Manage operator credentials, audit policies, console appearance, and telemetry transport streams.'
                  : 'Prioritize the highest-signal events, inspect the evidence trail, and move the incident forward.'}
              </p>
            </div>

            {/* 3 Executive Glassmorphic KPI Stat Cards */}
            <div className="grid grid-cols-3 gap-3">
              <div className="group relative rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.06] to-white/[0.015] p-4 backdrop-blur-2xl transition-all duration-300 hover:border-white/25 hover:from-white/[0.08] shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_16px_40px_-12px_rgba(0,0,0,0.85)] min-w-[110px]">
                <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 font-semibold">
                  {activeSection === 'settings' ? 'SECURITY' : 'TOTAL'}
                </div>
                <div className="mt-1 font-sans text-2xl font-bold tracking-tight text-white">
                  {activeSection === 'settings' ? 'HARDENED' : (overview?.total ?? 0)}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 font-sans truncate">
                  {activeSection === 'settings' ? 'Ledger verified' : 'Active buffer'}
                </div>
              </div>

              <div className="group relative rounded-2xl border border-primary/30 bg-gradient-to-b from-primary/10 via-white/[0.02] to-transparent p-4 backdrop-blur-2xl transition-all duration-300 hover:border-primary/55 shadow-[inset_0_1px_1px_rgba(56,189,248,0.25),0_16px_40px_-12px_rgba(0,0,0,0.85),0_0_20px_rgba(56,189,248,0.08)] min-w-[110px]">
                <div className="text-[10px] font-mono uppercase tracking-wider text-primary font-semibold">
                  {activeSection === 'settings' ? 'STREAM' : 'HIGH'}
                </div>
                <div className="mt-1 font-sans text-2xl font-bold tracking-tight text-primary">
                  {activeSection === 'settings' ? 'LIVE WS' : ((bySeverity?.critical ?? 0) + (bySeverity?.high ?? 0))}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 font-sans truncate">
                  {activeSection === 'settings' ? 'Transport live' : 'Immediate triage'}
                </div>
              </div>

              <div className="group relative rounded-2xl border border-emerald-500/30 bg-gradient-to-b from-emerald-500/10 via-white/[0.02] to-transparent p-4 backdrop-blur-2xl transition-all duration-300 hover:border-emerald-500/55 shadow-[inset_0_1px_1px_rgba(34,197,94,0.25),0_16px_40px_-12px_rgba(0,0,0,0.85),0_0_20px_rgba(34,197,94,0.06)] min-w-[110px]">
                <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-semibold">
                  {activeSection === 'settings' ? 'ACCESS' : 'MEDIUM'}
                </div>
                <div className="mt-1 font-sans text-2xl font-bold tracking-tight text-emerald-400">
                  {activeSection === 'settings' ? 'VERIFIED' : (bySeverity?.medium ?? 0)}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 font-sans truncate">
                  {activeSection === 'settings' ? 'Role Analyst' : 'Surveillance'}
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
            <div className="min-w-0">
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeSection}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                >
                  <WorkspacePanel
                    section={activeSection}
                    alerts={alerts}
                    filteredAlerts={filteredAlerts}
                    selected={selected}
                    onSelect={onSelect}
                    filters={filters}
                    onFilterChange={onFilterChange}
                    density={density}
                    onDensityChange={onDensityChange}
                    onAddAlert={onAddAlert}
                    onNavigate={handleNavigate}
                  />
                </motion.div>
              </AnimatePresence>
            </div>
            <RightRail onFilterChange={onFilterChange} />
          </div>
        </div>
      </main>

      <AnimatePresence>
        {selected && (
          <motion.div key="drawer-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <button type="button" className="fixed inset-0 z-40 bg-black/70 lg:hidden" onClick={onClose} aria-label="Close alert evidence" />
          </motion.div>
        )}
      </AnimatePresence>
      {selected && <AlertDetailDrawer alert={selected} onClose={onClose} />}

      <CommandPalette
        open={commandOpen}
        onOpenChange={setCommandOpen}
        onNavigate={handleNavigate}
      />
    </div>
  );
}
