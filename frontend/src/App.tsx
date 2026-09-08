import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { useMemo, useState, useEffect, useCallback } from 'react';
import type { AlertDetail, AlertSummary, Severity } from '@/types';
import { useAlertStream } from '@/hooks/useAlertStream';
import { StatsStrip } from '@/components/stats/StatsStrip';
import { LandingPage } from '@/components/ui/LandingPage';
import { AlertFeed, type FeedFilters } from '@/components/feed/AlertFeed';
import { ReplayBar } from '@/components/replay/ReplayBar';
import { AlertDrawer } from '@/components/drawer/AlertDrawer';
import { EvalPanel } from '@/components/eval/EvalPanel';
import { BenchmarkPanel } from '@/components/eval/BenchmarkPanel';
import { CommandBar } from '@/components/ui/CommandBar';
import { BackgroundStars } from '@/components/ui/BackgroundStars';
import { Sidebar, type TabId } from '@/components/ui/Sidebar';
import { OverviewPanel } from '@/components/panels/OverviewPanel';
import { SettingsPanel } from '@/components/ui/SettingsPanel';
import { ProfilePanel } from '@/components/ui/ProfilePanel';
import { HealthMetricsPanel } from '@/components/panels/HealthMetricsPanel';
import { EventVelocityPanel } from '@/components/panels/EventVelocityPanel';
import { AuditLogsPanel } from '@/components/panels/AuditLogsPanel';
import { ThreatClustersPanel } from '@/components/panels/ThreatClustersPanel';
import { RulesPanel } from '@/components/panels/RulesPanel';
import { PlaybooksPanel } from '@/components/panels/PlaybooksPanel';
import { NotificationsPanel } from '@/components/panels/NotificationsPanel';
import { ExportPanel } from '@/components/panels/ExportPanel';
import { motion, AnimatePresence } from 'framer-motion';
import { Sparkles, Info } from 'lucide-react';

const ALL_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const isLandingPage = location.pathname === '/';

  const {
    alerts,
    stats,
    connected,
    mode,
    setReplayMode,
    startReplay,
    replayStatus,
    fetchAlertDetail,
    pushCustomAlert,
    isLiveApi,
    systemNotice,
  } = useAlertStream();

  const [selectedSummary, setSelectedSummary] = useState<AlertSummary | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<AlertDetail | null>(null);
  const [commandOpen, setCommandOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [filters, setFilters] = useState<FeedFilters>({
    severities: new Set(ALL_SEVERITIES),
  });

  // Fetch full detail when an alert is selected
  const handleSelectAlert = useCallback(
    async (summary: AlertSummary) => {
      setSelectedSummary(summary);
      const detail = await fetchAlertDetail(summary.id);
      if (detail) {
        setSelectedDetail(detail);
      } else {
        // Fallback to basic object if detail not found
        setSelectedDetail(summary as AlertDetail);
      }
    },
    [fetchAlertDetail],
  );

  // Global Cmd+K or Ctrl+K keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const sortedAlerts = useMemo(
    () => [...(alerts || [])].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()),
    [alerts],
  );

  return (
    <div className="h-screen bg-void text-ink grid-noise relative flex flex-col overflow-hidden">
      <BackgroundStars />

      {/* Terminal status line */}
      {!isLandingPage && (
        <div className="sticky top-0 z-30">
          <StatsStrip stats={stats} connected={connected} onOpenCommand={() => setCommandOpen(true)} />
        </div>
      )}

      {/* System Notice Toast */}
      {systemNotice && (
        <div className="fixed top-12 right-6 z-50 font-mono text-xs px-4 py-2 rounded-md bg-slate-900 border border-sev-low text-ink shadow-2xl flex items-center gap-2">
          <Info size={14} className="text-sev-low" />
          <span>{systemNotice.message}</span>
        </div>
      )}

      <Routes>
        <Route
          path="/"
          element={
            <LandingPage
              key="landing"
              onEnter={() => navigate('/dashboard')}
              alerts={sortedAlerts}
              connected={connected}
            />
          }
        />
        <Route
          path="/login"
          element={<Navigate to="/" replace />}
        />
        <Route
          path="/dashboard"
          element={
            <div className="flex flex-1 overflow-hidden relative z-10 w-full">
              <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
              
              <div className="flex-1 overflow-y-auto custom-scrollbar">
                <motion.div
                  key="dashboard"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.8 }}
                  className="min-h-full flex flex-col"
                >
                  {/* Main content area */}
                  <motion.main
                    className="max-w-[1400px] mx-auto w-full px-4 lg:px-6 py-4 space-y-4 flex-1"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, ease: 'easeOut' }}
                  >
                    {activeTab === 'overview' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <OverviewPanel />
                      </motion.div>
                    )}

                    {activeTab === 'live_feed' && (
                      <>
                        <motion.div
                          initial={{ opacity: 0, scale: 0.98 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ duration: 0.4 }}
                        >
                          <ReplayBar
                            mode={mode}
                            onModeChange={setReplayMode}
                            replayStatus={replayStatus}
                            alertsPerMin={stats?.alerts_per_min ?? 0}
                            totalProcessed={stats?.total ?? 0}
                            onStartReplay={startReplay}
                          />
                        </motion.div>

                        <motion.div
                          className="grid grid-cols-1 lg:grid-cols-[1fr] gap-4"
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ duration: 0.4, delay: 0.1 }}
                        >
                          <div className="h-[580px]">
                            <AlertFeed
                              alerts={sortedAlerts}
                              onSelect={handleSelectAlert}
                              selectedId={selectedSummary?.id}
                              filters={filters}
                              onFiltersChange={setFilters}
                              onInjectCustomAlert={pushCustomAlert}
                            />
                          </div>
                        </motion.div>
                      </>
                    )}

                    {activeTab === 'evaluation' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6 }}
                      >
                        <EvalPanel />
                      </motion.div>
                    )}

                    {activeTab === 'benchmarks' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6 }}
                      >
                        <BenchmarkPanel />
                      </motion.div>
                    )}

                    {activeTab === 'settings' && (
                      <motion.div
                        className="w-full h-full pt-2"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6 }}
                      >
                        <SettingsPanel />
                      </motion.div>
                    )}

                    {activeTab === 'profile' && (
                      <motion.div
                        className="w-full h-full pt-2"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6 }}
                      >
                        <ProfilePanel />
                      </motion.div>
                    )}

                    {activeTab === 'health_metrics' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <HealthMetricsPanel />
                      </motion.div>
                    )}

                    {activeTab === 'event_velocity' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <EventVelocityPanel />
                      </motion.div>
                    )}

                    {activeTab === 'audit_logs' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <AuditLogsPanel />
                      </motion.div>
                    )}

                    {activeTab === 'threat_clusters' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <ThreatClustersPanel />
                      </motion.div>
                    )}

                    {activeTab === 'rules' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <RulesPanel />
                      </motion.div>
                    )}

                    {activeTab === 'playbooks' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <PlaybooksPanel />
                      </motion.div>
                    )}

                    {activeTab === 'notifications' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <NotificationsPanel />
                      </motion.div>
                    )}

                    {activeTab === 'export' && (
                      <motion.div
                        className="w-full pt-2"
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4 }}
                      >
                        <ExportPanel />
                      </motion.div>
                    )}
                  </motion.main>

                  <footer className="border-t border-edge mt-auto shrink-0">
                    <div className="max-w-[1400px] mx-auto px-4 lg:px-6 py-3 flex items-center justify-between flex-wrap gap-2">
                      <span className="font-mono text-[10px] text-dim uppercase tracking-[0.14em]">
                        Flare · FastAPI + LangGraph + SQLite + Chroma Backend API
                      </span>
                      <span className="font-mono text-[10px] text-dim">
                        severity escalation: threat intel score ≥ 50 overrides LLM severity
                      </span>
                    </div>
                  </footer>
                </motion.div>
              </div>
            </div>
          }
        />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>

      {/* Drill-down drawer */}
      {!isLandingPage && (
        <AlertDrawer alert={selectedDetail} onClose={() => { setSelectedSummary(null); setSelectedDetail(null); }} />
      )}

      {/* Mercury AI Command Bar */}
      {!isLandingPage && (
        <CommandBar
          isOpen={commandOpen}
          onClose={() => setCommandOpen(false)}
          alerts={sortedAlerts}
          onSelectAlert={(a) => handleSelectAlert(a)}
          onSetFilters={setFilters}
          onSetReplayMode={setReplayMode}
          onPushCustomAlert={pushCustomAlert}
        />
      )}
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`inline-block h-1.5 w-1.5 rounded-full ${color}`} />
      {label}
    </span>
  );
}
