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
    <div id="dashboard" className={`page-enter min-h-screen bg-background text-foreground ${density === 'compact' ? 'density-compact' : ''}`}>
      <TopBar
        ticker={overview?.ticker}
        paused={paused}
        onTogglePaused={onTogglePaused}
        onCommand={() => setCommandOpen(true)}
        onLogout={onLogout}
        connectionStatus={connectionStatus}
      />
      <DashSidebar
        activeSection={activeSection}
        onNavigate={handleNavigate}
      />
      <main className="min-h-[calc(100vh-3.5rem)] pt-14 lg:pl-56">
        <div className="mx-auto max-w-[1400px] px-4 py-6 lg:px-7 lg:py-8">
          <div className="mt-2 mb-5 flex items-end justify-between">
            <div>
              <div className="mono-label flex items-center gap-2">
                <span className={`h-1.5 w-1.5 rounded-full ${paused ? 'bg-yellow-500' : 'bg-signal animate-blink'}`} />
                {paused ? 'STREAM PAUSED' : 'STREAM ACTIVE'} <span className="text-muted-foreground">// {activeSection}</span>
              </div>
              <h1 className="font-display mt-2 text-4xl leading-[0.95] md:text-5xl">
                Incident command <span className="text-muted-foreground">/ live queue</span>
              </h1>
              <p className="mt-2 max-w-xl text-sm text-muted-foreground">
                Prioritize the highest-signal events, inspect the evidence trail, and move the incident forward.
              </p>
            </div>
            <div className="grid grid-cols-3 border border-border bg-card">
              <div className="border-r border-border px-4 py-3">
                <div className="mono-label text-[9px]">TOTAL</div>
                <div className="mt-1 font-mono text-xl text-foreground">{overview?.total ?? 0}</div>
              </div>
              <div className="border-r border-border px-4 py-3">
                <div className="mono-label text-[9px]">HIGH</div>
                <div className="mt-1 font-mono text-xl text-primary">{(bySeverity?.critical ?? 0) + (bySeverity?.high ?? 0)}</div>
              </div>
              <div className="px-4 py-3">
                <div className="mono-label text-[9px]">MEDIUM</div>
                <div className="mt-1 font-mono text-xl text-yellow-500">{bySeverity?.medium ?? 0}</div>
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
                  />
                </motion.div>
              </AnimatePresence>
            </div>
            <RightRail />
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
