import { useCallback, useEffect, useMemo, useState } from 'react';
import DashboardView from '../components/DashboardView.jsx';
import { useAuth } from '../contexts/AuthContext.jsx';
import { useAlertStream } from '../hooks/useAlertStream.js';

const API_BASE = import.meta.env.VITE_API_BASE || '';

// FE-17 (PLAN §3.3, I9). This page used to seed itself from
// `createMockAlerts()` whenever `import.meta.env.DEV` was true, and the
// SIMULATE control appended another invented alert on every click. FE-6's
// `GET /alerts` masked the seed by replacing the array on mount, but masked is
// not absent — a slow or failed hydrate left invented alerts on screen, and
// DEV is the branch that runs during every rehearsal. Both are gone, and
// `data/mockAlerts.js` went with them: DEV now populates exactly the way
// production does, from the real endpoint and the real stream.
const ALERT_PAGE_SIZE = 50;

export default function DashboardPage() {
  const { token, logout } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filters, setFilters] = useState({});
  const [activeSection, setActiveSection] = useState('overview');
  const [paused, setPaused] = useState(false);
  const [density, setDensity] = useState('comfortable');
  const [useWebSocket, setUseWebSocket] = useState(true);

  const updateFilters = useCallback((next) => {
    setFilters((current) => ({ ...current, ...next }));
    setSelected(null);
  }, []);

  const filteredAlerts = useMemo(() => {
    const query = filters.search?.trim().toLowerCase();
    return alerts.filter((alert) => {
      const matchesSeverity = !filters.severity || alert.severity === filters.severity;
      const matchesAttackType = !filters.attack_type || alert.attack_type === filters.attack_type;
      const haystack = [alert.id, alert.signature, alert.src_ip, alert.dest_ip, alert.attack_type, alert.mitre_technique].join(' ').toLowerCase();
      return matchesSeverity && matchesAttackType && (!query || haystack.includes(query));
    });
  }, [alerts, filters]);

  const handleWsAlert = useCallback((alert) => {
    setAlerts((current) => [{ ...alert }, ...current].slice(0, 200));
  }, []);

  const { connectionStatus, pause: wsPause, resume: wsResume } = useAlertStream(
    useWebSocket ? token : null,
    { paused, onAlert: handleWsAlert }
  );

  // FE-6: hydrate from the persisted list. Without this the feed starts empty
  // on every reload and only fills as new alerts arrive. FE-17 promoted it to a
  // callback so the toolbar control can re-run the same real fetch instead of
  // appending an invented alert.
  const hydrate = useCallback(async () => {
    if (!token) return;
    try {
      const response = await fetch(`${API_BASE}/api/v1/alerts?limit=${ALERT_PAGE_SIZE}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const d = await response.json();
      if (!d?.ok) return;
      const rows = Array.isArray(d.data) ? d.data : d.data?.alerts;
      if (Array.isArray(rows)) setAlerts(rows);
    } catch { /* live stream still hydrates the feed */ }
  }, [token]);

  useEffect(() => { hydrate(); }, [hydrate]);

  // SSE fallback
  useEffect(() => {
    if (useWebSocket || paused || !token) return undefined;
    let eventSource;
    try {
      eventSource = new EventSource(`${API_BASE}/api/v1/stream/token?token=${encodeURIComponent(token)}`);
      eventSource.onmessage = (event) => {
        try {
          const incoming = JSON.parse(event.data);
          if (incoming?.id) setAlerts((current) => [{ ...incoming }, ...current].slice(0, 200));
        } catch { /* ignore malformed events */ }
      };
      eventSource.onerror = () => { /* browser auto-reconnects */ };
    } catch { /* SSE not available */ }
    return () => eventSource?.close();
  }, [useWebSocket, paused, token]);

  useEffect(() => {
    if (paused) { if (useWebSocket) wsPause(); return; }
    if (useWebSocket) wsResume();
  }, [paused, useWebSocket, wsPause, wsResume]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement) return;
      if (event.key === 'Escape') { setSelected(null); return; }
      if (activeSection !== 'feed' && activeSection !== 'overview') return;
      if (event.key === 'j' || event.key === 'ArrowDown') {
        event.preventDefault();
        setSelected((current) => {
          const idx = filteredAlerts.findIndex((a) => a.id === current?.id);
          return filteredAlerts[Math.min(idx + 1, filteredAlerts.length - 1)] || null;
        });
      }
      if (event.key === 'k' || event.key === 'ArrowUp') {
        event.preventDefault();
        setSelected((current) => {
          const idx = filteredAlerts.findIndex((a) => a.id === current?.id);
          return filteredAlerts[Math.max(idx <= 0 ? 1 : idx - 1, 0)] || null;
        });
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeSection, filteredAlerts]);

  // FE-17. The toolbar control used to append a fabricated alert in DEV and do
  // nothing at all in production — a control wired to a mock in one environment
  // and to nothing in the other. It now re-reads the persisted list, which is a
  // real action with a real effect in every environment.
  const handleAddAlert = useCallback(() => {
    if (paused) return;
    hydrate();
  }, [paused, hydrate]);

  const handleNavigate = useCallback((section) => {
    setActiveSection(section);
    setSelected(null);
  }, []);

  return (
    <DashboardView
      alerts={alerts}
      filteredAlerts={filteredAlerts}
      selected={selected}
      onSelect={setSelected}
      onClose={() => setSelected(null)}
      filters={filters}
      onFilterChange={updateFilters}
      activeSection={activeSection}
      onNavigate={handleNavigate}
      paused={paused}
      onTogglePaused={() => setPaused((c) => !c)}
      density={density}
      onDensityChange={setDensity}
      onAddAlert={handleAddAlert}
      onLogout={logout}
      connectionStatus={useWebSocket ? connectionStatus : 'connected'}
    />
  );
}
