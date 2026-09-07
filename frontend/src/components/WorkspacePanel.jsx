import { motion } from 'motion/react';
import { useEffect, useState } from 'react';
import AnimatedNumber from './AnimatedNumber.jsx';
import StatusDot from './StatusDot.jsx';
import AlertTable from './AlertTable.jsx';
import FilterStrip from './FilterStrip.jsx';

const API_BASE = import.meta.env.VITE_API_BASE || '';

function HealthPanel() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHealth = async () => {
    try {
      const token = localStorage.getItem('flare_token');
      const res = await fetch(`${API_BASE}/api/v1/health`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        if (res.status === 401) throw new Error('Authentication required — please log in again.');
        if (res.status === 403) throw new Error('Access denied.');
        const body = await res.text();
        throw new Error(body || `Health check failed: ${res.status}`);
      }
      const json = await res.json();
      setHealth(json.data || json);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to load health data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const id = setInterval(fetchHealth, 30000);
    return () => clearInterval(id);
  }, []);

  if (loading) {
    return (
      <section className="dashboard-panel">
        <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
          <div>
            <div className="eyebrow text-ash-dark">External dependencies</div>
            <h2 className="mt-1 text-base font-semibold text-paper">Health metrics</h2>
          </div>
          <button type="button" onClick={fetchHealth} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Refresh</button>
        </div>
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading health data...</div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="dashboard-panel">
        <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
          <div>
            <div className="eyebrow text-ash-dark">External dependencies</div>
            <h2 className="mt-1 text-base font-semibold text-paper">Health metrics</h2>
          </div>
          <button type="button" onClick={() => { setLoading(true); setError(null); fetchHealth(); }} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Retry</button>
        </div>
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-red">{error}</div>
      </section>
    );
  }

  const services = health?.services || [];
  return (
    <section className="dashboard-panel">
      <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
        <div>
          <div className="eyebrow text-ash-dark">External dependencies</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Health metrics</h2>
        </div>
        <button type="button" onClick={fetchHealth} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Refresh</button>
      </div>
      <div className="divide-y divide-line">
        {services.map((service, index) => {
          const tone = service.status === 'ok' ? 'live' : service.status === 'rate_limited' ? 'medium' : 'offline';
          const toneColor = service.status === 'ok' ? 'text-green' : service.status === 'rate_limited' ? 'text-amber' : 'text-red';
          return (
            <motion.div
              key={service.name}
              className="flex items-center justify-between gap-4 px-4 py-5"
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.08 }}
            >
              <div className="flex items-center gap-3">
                <StatusDot tone={tone} pulse={tone === 'live'} />
                <div>
                  <div className="font-mono-ui text-xs text-paper">{service.name}</div>
                  <div className="mt-1 font-mono-ui text-[10px] text-ash-dark">{service.message || 'external API'}</div>
                </div>
              </div>
              <div className={`font-mono-ui text-[10px] ${toneColor}`}>
                {service.latency_ms != null ? `${service.latency_ms}ms` : service.status?.toUpperCase()}
              </div>
            </motion.div>
          );
        })}
        {services.length === 0 && (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">No services configured</div>
        )}
      </div>
    </section>
  );
}

function TimelinePanel() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    try {
      const token = localStorage.getItem('flare_token');
      const res = await fetch(`${API_BASE}/api/v1/stats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        if (res.status === 401) throw new Error('Authentication required — please log in again.');
        if (res.status === 403) throw new Error('Access denied.');
        throw new Error(`Failed to load timeline: ${res.status}`);
      }
      const json = await res.json();
      setStats(json.data || json);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to load timeline');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const timeline = stats?.timeline || [];
  const maxCount = Math.max(...timeline.map((t) => t.count), 1);
  const velocity = stats?.alert_velocity || 0;

  if (loading) {
    return (
      <section className="dashboard-panel">
        <div className="flex items-end justify-between border-b border-line-strong px-4 py-4">
          <div>
            <div className="eyebrow text-ash-dark">30 minute window</div>
            <h2 className="mt-1 text-base font-semibold text-paper">Event velocity</h2>
          </div>
        </div>
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading timeline...</div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="dashboard-panel">
        <div className="flex items-end justify-between border-b border-line-strong px-4 py-4">
          <div>
            <div className="eyebrow text-ash-dark">30 minute window</div>
            <h2 className="mt-1 text-base font-semibold text-paper">Event velocity</h2>
          </div>
          <button type="button" onClick={() => { setLoading(true); setError(null); fetchStats(); }} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Retry</button>
        </div>
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-red">{error}</div>
      </section>
    );
  }

  return (
    <section className="dashboard-panel">
      <div className="flex items-end justify-between border-b border-line-strong px-4 py-4">
        <div>
          <div className="eyebrow text-ash-dark">30 minute window</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Event velocity</h2>
        </div>
        <span className="font-mono-ui text-[10px] text-amber">{velocity} alerts/min</span>
      </div>
      <div className="p-5">
        {timeline.length === 0 ? (
          <div className="flex h-64 items-center justify-center border-b border-l border-line-strong">
            <div className="font-mono-ui text-[10px] text-ash-dark">No timeline data yet. Alerts will appear here.</div>
          </div>
        ) : (
          <div className="flex h-64 items-end gap-2 border-b border-l border-line-strong px-3 pb-0 pt-4">
            {timeline.slice(-20).map((entry, index) => (
              <div key={entry.time} className="group flex h-full flex-1 items-end">
                <motion.div
                  className="timeline-bar w-full bg-amber/45"
                  initial={{ scaleY: 0 }}
                  animate={{ scaleY: 1 }}
                  transition={{ delay: index * 0.025, duration: 0.5 }}
                  style={{ height: `${(entry.count / maxCount) * 100}%`, transformOrigin: 'bottom' }}
                  title={`${entry.time}: ${entry.count} alerts`}
                />
              </div>
            ))}
          </div>
        )}
        <div className="mt-3 flex justify-between font-mono-ui text-[9px] uppercase tracking-[0.08em] text-ash-dark">
          <span>{timeline.length > 0 ? timeline[0]?.time?.slice(11, 16) : '--:--'}</span>
          <span>{timeline.length > 0 ? timeline[timeline.length - 1]?.time?.slice(11, 16) : '--:--'}</span>
          <span>now</span>
        </div>
      </div>
    </section>
  );
}

function AuditLogsPanel() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [offset, setOffset] = useState(0);
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [expanded, setExpanded] = useState(null);

  const limit = 25;

  const fetchLogs = async (reset = false) => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('flare_token');
      const params = new URLSearchParams({ limit: String(limit), offset: String(reset ? 0 : offset) });
      if (actionFilter) params.set('action', actionFilter);
      if (resourceFilter) params.set('resource_type', resourceFilter);
      const adminRes = await fetch(`${API_BASE}/api/v1/audit/logs?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      let data;
      if (adminRes.status === 403) {
        const meRes = await fetch(`${API_BASE}/api/v1/audit/logs/me?${params}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!meRes.ok) throw new Error(`Failed to load audit logs: ${meRes.status}`);
        data = await meRes.json();
      } else if (!adminRes.ok) {
        throw new Error(`Failed to load audit logs: ${adminRes.status}`);
      } else {
        data = await adminRes.json();
      }
      const payload = data.data || data;
      setLogs(payload.logs || []);
      setTotal(payload.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(true); }, [actionFilter, resourceFilter]);

  const pages = Math.max(1, Math.ceil(total / limit));
  const currentPage = Math.floor(offset / limit) + 1;

  const uniqueActions = [...new Set(logs.map((l) => l.action))];

  return (
    <section className="dashboard-panel">
      <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
        <div>
          <div className="eyebrow text-ash-dark">System audit trail // {total} events</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Audit logs</h2>
        </div>
        <button type="button" onClick={() => fetchLogs(true)} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Refresh</button>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-line px-4 py-3">
        <select value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setOffset(0); }} className="border border-line-strong bg-ink-900 px-2 py-1.5 font-mono-ui text-[10px] text-paper">
          <option value="">All actions</option>
          {uniqueActions.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select value={resourceFilter} onChange={(e) => { setResourceFilter(e.target.value); setOffset(0); }} className="border border-line-strong bg-ink-900 px-2 py-1.5 font-mono-ui text-[10px] text-paper">
          <option value="">All resources</option>
          <option value="rule">rule</option>
          <option value="playbook">playbook</option>
          <option value="user">user</option>
          <option value="alert">alert</option>
        </select>
      </div>

      {loading ? (
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading audit logs...</div>
      ) : error ? (
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-red">{error}</div>
      ) : logs.length === 0 ? (
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">No audit events recorded yet.</div>
      ) : (
        <div className="divide-y divide-line">
          {logs.map((log) => (
            <div key={log.id} className="px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="shrink-0 bg-amber/15 px-1.5 py-0.5 font-mono-ui text-[9px] text-amber">{log.action}</span>
                  <span className="font-mono-ui text-xs text-paper truncate">{log.resource_type}{log.resource_id ? ` #${log.resource_id}` : ''}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono-ui text-[9px] text-ash-dark">{log.created_at?.replace('T', ' ').slice(0, 19)}</span>
                  {log.details && (
                    <button type="button" onClick={() => setExpanded(expanded === log.id ? null : log.id)} className="font-mono-ui text-[9px] text-amber hover:text-amber/80">
                      {expanded === log.id ? 'hide' : 'details'}
                    </button>
                  )}
                </div>
              </div>
              {expanded === log.id && log.details && (
                <pre className="mt-2 max-h-40 overflow-auto border border-line-strong bg-ink-950 p-2 font-mono-ui text-[9px] text-ash leading-4">
                  {JSON.stringify(log.details, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between border-t border-line px-4 py-3 font-mono-ui text-[10px] text-ash-dark">
        <span>Page {currentPage} / {pages}</span>
        <div className="flex gap-2">
          <button type="button" disabled={currentPage <= 1} onClick={() => { setOffset((currentPage - 2) * limit); fetchLogs(); }} className="px-2 py-1 text-amber disabled:opacity-30 hover:text-amber/80">Prev</button>
          <button type="button" disabled={currentPage >= pages} onClick={() => { setOffset(currentPage * limit); fetchLogs(); }} className="px-2 py-1 text-amber disabled:opacity-30 hover:text-amber/80">Next</button>
        </div>
      </div>
    </section>
  );
}

function EvalPanel() {
  const [evalData, setEvalData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchEval = async (force = false) => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('flare_token');
      const res = await fetch(`${API_BASE}/api/v1/eval${force ? '?force=true' : ''}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        if (res.status === 401) throw new Error('Authentication required — please log in again.');
        if (res.status === 403) throw new Error('Access denied.');
        throw new Error(`Failed to load eval: ${res.status}`);
      }
      const json = await res.json();
      setEvalData(json.data || json);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to load eval data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEval();
  }, []);

  if (loading) {
    return (
      <section className="dashboard-panel">
        <div className="border-b border-line-strong px-4 py-4">
          <div className="eyebrow text-ash-dark">Evaluation</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Classification evaluation</h2>
        </div>
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading eval data...</div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="dashboard-panel">
        <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
          <div>
            <div className="eyebrow text-ash-dark">Evaluation</div>
            <h2 className="mt-1 text-base font-semibold text-paper">Classification evaluation</h2>
          </div>
          <button type="button" onClick={() => { setLoading(true); setError(null); fetchEval(); }} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Retry</button>
        </div>
        <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-red">{error}</div>
      </section>
    );
  }

  // FE-8 + FE-16 (PLAN §3.3). The fallbacks used to be a 3x3 grid of literal
  // zeros and a 3-label axis, under a hardcoded `grid-cols-4` that renders one
  // header column plus three data columns — so the axis, the width and the
  // content already disagreed before any real data arrived, and a 4x4 matrix
  // wrapped its last column onto the next row. Both fallbacks are gone: a
  // matrix of zeros is a picture of a measurement nobody took. The grid is now
  // sized off `labels`, so the width follows the class list rather than
  // pinning it.
  const matrix = evalData?.confusion_matrix?.matrix || [];
  const labels = evalData?.confusion_matrix?.labels || [];
  const breakdown = evalData?.attack_type_breakdown || {};
  const misclassified = evalData?.rows?.filter((r) => r.pred_severity !== r.true_severity || r.pred_attack_type !== r.true_attack_type) || [];
  const sampleSize = evalData?.sample_size || 0;
  const highF1 = evalData?.high_severity_f1 || 0;
  const avgLatency = evalData?.avg_latency_ms || 0;

  return (
    <section className="dashboard-panel">
      <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
        <div>
          <div className="eyebrow text-ash-dark">{sampleSize} labeled alerts</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Classification evaluation</h2>
        </div>
        <button type="button" onClick={() => fetchEval(true)} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">Refresh</button>
      </div>
      <div className="grid gap-4 p-4 md:grid-cols-3">
        <div className="metric-block border border-line-strong p-4">
          <div className="font-mono-ui text-[9px] text-ash-dark">SEVERITY ACCURACY</div>
          <div className="mt-2 font-mono-ui text-3xl text-amber"><AnimatedNumber value={evalData?.severity_accuracy || 0} decimals={2} /></div>
        </div>
        <div className="metric-block border border-line-strong p-4">
          <div className="font-mono-ui text-[9px] text-ash-dark">ATTACK TYPE ACCURACY</div>
          <div className="mt-2 font-mono-ui text-3xl text-cyan"><AnimatedNumber value={evalData?.attack_type_accuracy || 0} decimals={2} /></div>
        </div>
        <div className="metric-block border border-line-strong p-4">
          <div className="font-mono-ui text-[9px] text-ash-dark">AVG LATENCY</div>
          <div className="mt-2 font-mono-ui text-3xl text-cyan"><AnimatedNumber value={avgLatency} suffix="ms" decimals={0} /></div>
        </div>
        <div className="metric-block border border-line-strong p-4">
          <div className="font-mono-ui text-[9px] text-ash-dark">HIGH PRECISION</div>
          <div className="mt-2 font-mono-ui text-3xl text-green"><AnimatedNumber value={evalData?.high_severity_precision ?? 0} decimals={2} /></div>
        </div>
        <div className="metric-block border border-line-strong p-4">
          <div className="font-mono-ui text-[9px] text-ash-dark">HIGH RECALL</div>
          <div className="mt-2 font-mono-ui text-3xl text-green"><AnimatedNumber value={evalData?.high_severity_recall ?? 0} decimals={2} /></div>
        </div>
        <div className="metric-block border border-line-strong p-4">
          <div className="font-mono-ui text-[9px] text-ash-dark">HIGH F1</div>
          <div className="mt-2 font-mono-ui text-3xl text-green"><AnimatedNumber value={highF1 || 0} decimals={2} /></div>
        </div>
      </div>
      <div className="border-t border-line p-4">
        <div className="eyebrow mb-4 text-ash-dark">Confusion matrix // actual x predicted</div>
        <div
          className="grid max-w-[360px] gap-1 font-mono-ui text-[10px]"
          style={{ gridTemplateColumns: `repeat(${labels.length + 1}, minmax(0, 1fr))` }}
        >
          <div />
          {labels.map((l) => <div key={l} className="p-2 text-center text-ash-dark">{l.toUpperCase()}</div>)}
          {labels.map((label, row) => (
            <div key={label} className="contents">
              <div className="p-2 text-right text-ash-dark">{label.toUpperCase()}</div>
              {matrix[row]?.map((value, col) => (
                <motion.div
                  key={`${row}-${col}`}
                  className={`p-3 text-center ${row === col ? 'bg-green/15 text-green' : 'bg-red/10 text-red'}`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: (row * labels.length + col) * 0.06 }}
                >
                  {value}
                </motion.div>
              ))}
            </div>
          ))}
          {labels.length === 0 && (
            <div className="col-span-full py-6 text-center text-ash-dark">No matrix in this run.</div>
          )}
        </div>
      </div>
      <div className="border-t border-line p-4">
        <div className="eyebrow mb-3 text-ash-dark">Attack type breakdown</div>
        <div className="grid gap-2 md:grid-cols-2">
          {Object.entries(breakdown).map(([atk, data]) => (
            <div key={atk} className="flex items-center justify-between border border-line-strong px-3 py-2 font-mono-ui text-[10px]">
              <span className="text-paper">{atk}</span>
              <span className="text-amber">{data.correct}/{data.true_count} ({Math.round((data.accuracy || 0) * 100)}%)</span>
            </div>
          ))}
          {Object.keys(breakdown).length === 0 && (
            <div className="font-mono-ui text-[10px] text-ash-dark">No breakdown data.</div>
          )}
        </div>
      </div>
      <div className="border-t border-line p-4">
        <div className="eyebrow mb-3 text-ash-dark">Misclassified ({evalData?.misclassified_count ?? 0})</div>
        <div className="max-h-48 overflow-y-auto space-y-1">
          {misclassified.slice(0, 20).map((r, i) => (
            <div key={i} className="flex items-center justify-between border border-line px-3 py-1.5 font-mono-ui text-[9px]">
              <span className="text-ash-dark truncate flex-1">{r.signature?.slice(0, 60)}</span>
              <span className="text-red ml-2">true:{r.true_severity}/{r.true_attack_type}</span>
              <span className="text-amber ml-2">pred:{r.pred_severity}/{r.pred_attack_type}</span>
            </div>
          ))}
          {misclassified.length === 0 && (
            <div className="font-mono-ui text-[10px] text-ash-dark">No misclassifications.</div>
          )}
        </div>
      </div>
    </section>
  );
}

// FE-13 (PLAN §3.3). This used to reduce the 200-alert browser buffer and call
// every source IP with one alert a "cluster": no threshold, and nothing older
// than the buffer was visible. `GET /alerts/clusters` applies a real
// `min_alerts` floor over the whole alerts table inside a window, so a single
// alert is no longer a correlation and history is no longer invisible.
function CorrelatedPanel({ onFilterChange }) {
  const [clusters, setClusters] = useState([]);
  const [meta, setMeta] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const token = localStorage.getItem('flare_token');
        const res = await fetch(`${API_BASE}/api/v1/alerts/clusters`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const json = await res.json();
        const data = json.data || json;
        if (cancelled) return;
        setClusters(Array.isArray(data.clusters) ? data.clusters : []);
        setMeta(data);
      } catch { /* the empty state below is the honest render */ }
      finally { if (!cancelled) setLoading(false); }
    };
    load();
    // The correlation job replaces the stored aggregate on its own interval;
    // re-reading it more often than that would re-fetch the same rows.
    const id = setInterval(load, 120000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return (
    <section className="dashboard-panel">
      <div className="border-b border-line-strong px-4 py-4">
        <div className="eyebrow text-ash-dark">Source IP correlation</div>
        <h2 className="mt-1 text-base font-semibold text-paper">Threat clusters</h2>
      </div>
      <div className="divide-y divide-line">
        {clusters.map((cluster, index) => (
          <motion.button
            type="button"
            key={cluster.src_ip}
            className="cluster-row flex w-full items-center justify-between gap-4 px-4 py-5 text-left transition-colors hover:bg-amber/5"
            onClick={() => onFilterChange({ search: cluster.src_ip })}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.06 }}
          >
            <div>
              <div className="font-mono-ui text-sm text-paper">{cluster.src_ip}</div>
              <div className="mt-1 font-mono-ui text-[10px] uppercase tracking-[0.08em] text-ash-dark">{(cluster.attack_types || []).join(' // ')}</div>
            </div>
            <div className="text-right">
              <div className="font-mono-ui text-lg text-amber">{String(cluster.alert_count).padStart(2, '0')}</div>
              <div className="font-mono-ui text-[9px] text-ash-dark">linked alerts</div>
            </div>
          </motion.button>
        ))}
        {clusters.length === 0 && (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">
            {loading
              ? 'Loading clusters...'
              : `No source IP has reached ${meta?.min_alerts ?? 'the'} linked alerts in the last ${meta?.window_minutes ?? '—'} minutes`}
          </div>
        )}
      </div>
    </section>
  );
}

function SeverityChart({ alerts }) {
  const counts = { high: 0, medium: 0, low: 0 };
  alerts.forEach((a) => { if (counts[a.severity] !== undefined) counts[a.severity] += 1; });
  const total = alerts.length || 1;
  const segments = [
    { label: 'HIGH', count: counts.high, color: '#e94560', pct: (counts.high / total) * 100 },
    { label: 'MED', count: counts.medium, color: '#f59e0b', pct: (counts.medium / total) * 100 },
    { label: 'LOW', count: counts.low, color: '#30d158', pct: (counts.low / total) * 100 },
  ];

  let offset = 0;
  const radius = 40;
  const circumference = 2 * Math.PI * radius;

  return (
    <section className="dashboard-panel p-4">
      <div className="eyebrow text-ash-dark">Severity distribution</div>
      <div className="mt-4 flex items-center gap-6">
        <div className="relative">
          <svg width="110" height="110" viewBox="0 0 100 100">
            {segments.map((seg) => {
              const dash = (seg.pct / 100) * circumference;
              const el = (
                <circle
                  key={seg.label}
                  cx="50" cy="50" r={radius}
                  fill="none"
                  stroke={seg.color}
                  strokeWidth="12"
                  strokeDasharray={`${dash} ${circumference - dash}`}
                  strokeDashoffset={-offset}
                  transform="rotate(-90 50 50)"
                  style={{ transition: 'stroke-dasharray 0.5s ease' }}
                />
              );
              offset += dash;
              return el;
            })}
            <text x="50" y="48" textAnchor="middle" fill="#e0e0e0" fontSize="14" fontWeight="bold" fontFamily="monospace">{total}</text>
            <text x="50" y="60" textAnchor="middle" fill="#666" fontSize="7" fontFamily="monospace">ALERTS</text>
          </svg>
        </div>
        <div className="space-y-2">
          {segments.map((seg) => (
            <div key={seg.label} className="flex items-center gap-3 font-mono-ui text-[10px]">
              <span className="h-2 w-2 rounded-full" style={{ background: seg.color }} />
              <span className="w-10 text-ash-dark">{seg.label}</span>
              <span className="text-paper">{seg.count}</span>
              <span className="text-ash-dark">{seg.pct.toFixed(0)}%</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ExportPanel({ filters }) {
  const [exporting, setExporting] = useState(null);

  const handleExport = async (format) => {
    setExporting(format);
    const params = new URLSearchParams();
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.attack_type) params.set('attack_type', filters.attack_type);
    if (filters.search) params.set('search', filters.search);
    params.set('limit', '500');

    try {
      const token = localStorage.getItem('flare_token');
      const res = await fetch(`${API_BASE}/api/v1/export/alerts/${format}?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `flare_alerts.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
    } finally {
      setExporting(null);
    }
  };

  return (
    <section className="dashboard-panel p-4">
      <div className="eyebrow text-ash-dark">Export data</div>
      <div className="mt-4 space-y-3">
        <button
          type="button"
          onClick={() => handleExport('csv')}
          disabled={exporting === 'csv'}
          className="flex w-full items-center gap-3 border border-line-strong bg-ink-900 px-4 py-3 font-mono-ui text-[10px] text-paper transition-colors hover:border-green/50 hover:bg-green/5 disabled:opacity-50"
        >
          <span className="text-green">CSV</span>
          <span className="text-ash-dark">{exporting === 'csv' ? 'Exporting...' : 'Download filtered alerts as CSV'}</span>
        </button>
        <button
          type="button"
          onClick={() => handleExport('pdf')}
          disabled={exporting === 'pdf'}
          className="flex w-full items-center gap-3 border border-line-strong bg-ink-900 px-4 py-3 font-mono-ui text-[10px] text-paper transition-colors hover:border-red/50 hover:bg-red/5 disabled:opacity-50"
        >
          <span className="text-red">PDF</span>
          <span className="text-ash-dark">{exporting === 'pdf' ? 'Exporting...' : 'Generate formatted PDF report'}</span>
        </button>
      </div>
    </section>
  );
}

function RulesPanel() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', conditions: { logic: 'AND', conditions: [{ field: 'severity', operator: 'equals', value: 'high' }] }, actions: [{ type: 'set_severity', value: 'high' }] });
  const [error, setError] = useState('');

  const fetchRules = () => {
    const token = localStorage.getItem('flare_token');
    fetch(`${API_BASE}/api/v1/rules`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => { setRules(d.rules || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchRules(); }, []);

  const handleCreate = async () => {
    setError('');
    const token = localStorage.getItem('flare_token');
    try {
      const res = await fetch(`${API_BASE}/api/v1/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(form),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Failed'); }
      setShowForm(false);
      setForm({ name: '', description: '', conditions: { logic: 'AND', conditions: [{ field: 'severity', operator: 'equals', value: 'high' }] }, actions: [{ type: 'set_severity', value: 'high' }] });
      fetchRules();
    } catch (err) { setError(err.message); }
  };

  const handleDelete = async (id) => {
    const token = localStorage.getItem('flare_token');
    await fetch(`${API_BASE}/api/v1/rules/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
    fetchRules();
  };

  return (
    <section className="dashboard-panel">
      <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
        <div>
          <div className="eyebrow text-ash-dark">Custom rules</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Alert rules</h2>
        </div>
        <button type="button" onClick={() => setShowForm(!showForm)} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">
          {showForm ? 'Cancel' : '+ New Rule'}
        </button>
      </div>

      {showForm && (
        <div className="border-b border-line p-4 space-y-3">
          {error && <div className="font-mono-ui text-[10px] text-red">{error}</div>}
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="Rule name"
            className="w-full border border-line-strong bg-ink-900 px-3 py-2 font-mono-ui text-[11px] text-paper outline-none"
          />
          <input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="Description (optional)"
            className="w-full border border-line-strong bg-ink-900 px-3 py-2 font-mono-ui text-[11px] text-paper outline-none"
          />
          <div className="grid grid-cols-3 gap-2">
            <select value={form.conditions.conditions[0].field} onChange={(e) => setForm({ ...form, conditions: { ...form.conditions, conditions: [{ ...form.conditions.conditions[0], field: e.target.value }] } })} className="border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper">
              <option value="severity">Severity</option>
              <option value="attack_type">Attack Type</option>
              <option value="src_ip">Source IP</option>
              <option value="dest_port">Dest Port</option>
            </select>
            <select value={form.conditions.conditions[0].operator} onChange={(e) => setForm({ ...form, conditions: { ...form.conditions, conditions: [{ ...form.conditions.conditions[0], operator: e.target.value }] } })} className="border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper">
              <option value="equals">Equals</option>
              <option value="contains">Contains</option>
              <option value="not_equals">Not Equals</option>
              <option value="greater_than">Greater Than</option>
            </select>
            <input
              value={form.conditions.conditions[0].value}
              onChange={(e) => setForm({ ...form, conditions: { ...form.conditions, conditions: [{ ...form.conditions.conditions[0], value: e.target.value }] } })}
              placeholder="Value"
              className="border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper outline-none"
            />
          </div>
          <button type="button" onClick={handleCreate} className="w-full bg-amber/20 border border-amber/40 py-2 font-mono-ui text-[10px] text-amber hover:bg-amber/30">
            Create Rule
          </button>
        </div>
      )}

      <div className="divide-y divide-line">
        {loading ? (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading...</div>
        ) : rules.length === 0 ? (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">No rules yet. Create one to customize alert handling.</div>
        ) : (
          rules.map((rule) => (
            <div key={rule.id} className="flex items-center justify-between px-4 py-4">
              <div>
                <div className="font-mono-ui text-xs text-paper">{rule.name}</div>
                <div className="mt-1 font-mono-ui text-[10px] text-ash-dark">{rule.description || 'No description'}</div>
                <div className="mt-1 font-mono-ui text-[9px] text-amber">{rule.match_count} matches</div>
              </div>
              <div className="flex items-center gap-2">
                <StatusDot tone={rule.is_enabled ? 'live' : 'offline'} />
                <button type="button" onClick={() => handleDelete(rule.id)} className="font-mono-ui text-[10px] text-red hover:text-red/80">Delete</button>
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function PlaybooksPanel({ selected }) {
  const [playbooks, setPlaybooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({ name: '', description: '', alert_type: '', severity_threshold: '', steps: [{ type: 'manual', title: '', description: '' }] });
  const [error, setError] = useState('');
  const [executing, setExecuting] = useState(null);
  const [execution, setExecution] = useState(null);
  const [busy, setBusy] = useState(false);

  const fetchPlaybooks = () => {
    const token = localStorage.getItem('flare_token');
    fetch(`${API_BASE}/api/v1/playbooks`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => { setPlaybooks(d.playbooks || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchPlaybooks(); }, []);

  useEffect(() => {
    if (!execution?.id) return undefined;
    if (execution.status === 'completed') return undefined;
    const id = setInterval(async () => {
      const token = localStorage.getItem('flare_token');
      const res = await fetch(`${API_BASE}/api/v1/playbooks/executions/${execution.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) setExecution(await res.json());
    }, 3000);
    return () => clearInterval(id);
  }, [execution?.id, execution?.status]);

  const resetForm = () => {
    setForm({ name: '', description: '', alert_type: '', severity_threshold: '', steps: [{ type: 'manual', title: '', description: '' }] });
    setEditing(null);
    setShowForm(false);
  };

  const openEdit = (pb) => {
    setForm({
      name: pb.name || '',
      description: pb.description || '',
      alert_type: pb.alert_type || '',
      severity_threshold: pb.severity_threshold || '',
      steps: pb.steps?.length ? pb.steps.map((s) => ({ type: s.type || 'manual', title: s.title || s.label || '', description: s.description || '' })) : [{ type: 'manual', title: '', description: '' }],
    });
    setEditing(pb.id);
    setShowForm(true);
    setError('');
  };

  const handleSubmit = async () => {
    setError('');
    const token = localStorage.getItem('flare_token');
    const payload = { ...form, steps: form.steps.filter((s) => s.title) };
    try {
      const res = await fetch(`${API_BASE}/api/v1/playbooks${editing ? `/${editing}` : ''}`, {
        method: editing ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Failed'); }
      resetForm();
      fetchPlaybooks();
    } catch (err) { setError(err.message); }
  };

  const handleDelete = async (id) => {
    const token = localStorage.getItem('flare_token');
    await fetch(`${API_BASE}/api/v1/playbooks/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
    fetchPlaybooks();
  };

  const handleExecute = async (pb) => {
    setBusy(true);
    setError('');
    const token = localStorage.getItem('flare_token');
    try {
      const params = new URLSearchParams();
      if (selected?.id) params.set('alert_id', selected.id);
      const res = await fetch(`${API_BASE}/api/v1/playbooks/${pb.id}/execute?${params}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Execute failed'); }
      const data = await res.json();
      const statusRes = await fetch(`${API_BASE}/api/v1/playbooks/executions/${data.execution_id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setExecution(statusRes.ok ? await statusRes.json() : { id: data.execution_id, status: 'in_progress', steps: pb.steps, completed_steps: [], current_step: 0 });
    } catch (err) { setError(err.message); }
    setBusy(false);
  };

  const handleCompleteStep = async (executionId, stepIndex) => {
    const token = localStorage.getItem('flare_token');
    const res = await fetch(`${API_BASE}/api/v1/playbooks/executions/${executionId}/steps/${stepIndex}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ notes: '' }),
    });
    if (res.ok) {
      const refreshed = await fetch(`${API_BASE}/api/v1/playbooks/executions/${executionId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (refreshed.ok) setExecution(await refreshed.json());
    }
  };

  const closeExecution = () => { setExecution(null); fetchPlaybooks(); };

  return (
    <section className="dashboard-panel">
      <div className="flex items-center justify-between border-b border-line-strong px-4 py-4">
        <div>
          <div className="eyebrow text-ash-dark">Incident response</div>
          <h2 className="mt-1 text-base font-semibold text-paper">Playbooks</h2>
        </div>
        <button type="button" onClick={() => { setShowForm(!showForm); if (showForm) resetForm(); }} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">
          {showForm ? 'Cancel' : '+ New Playbook'}
        </button>
      </div>

      {error && <div className="border-b border-line px-4 py-2 font-mono-ui text-[10px] text-red">{error}</div>}

      {showForm && (
        <div className="border-b border-line p-4 space-y-3">
          <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Playbook name" className="w-full border border-line-strong bg-ink-900 px-3 py-2 font-mono-ui text-[11px] text-paper outline-none" />
          <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Description" className="w-full border border-line-strong bg-ink-900 px-3 py-2 font-mono-ui text-[11px] text-paper outline-none" />
          <div className="grid grid-cols-2 gap-2">
            <input value={form.alert_type} onChange={(e) => setForm({ ...form, alert_type: e.target.value })} placeholder="Alert type (e.g. ddos)" className="border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper outline-none" />
            <select value={form.severity_threshold} onChange={(e) => setForm({ ...form, severity_threshold: e.target.value })} className="border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper">
              <option value="">Any severity</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </div>
          <div className="space-y-2">
            {form.steps.map((step, i) => (
              <div key={i} className="flex gap-2">
                <select value={step.type} onChange={(e) => { const s = [...form.steps]; s[i] = { ...s[i], type: e.target.value }; setForm({ ...form, steps: s }); }} className="border border-line-strong bg-ink-900 px-1 py-1 font-mono-ui text-[10px] text-paper">
                  <option value="manual">manual</option>
                  <option value="auto">auto</option>
                  <option value="approval">approval</option>
                </select>
                <input value={step.title} onChange={(e) => { const s = [...form.steps]; s[i] = { ...s[i], title: e.target.value }; setForm({ ...form, steps: s }); }} placeholder={`Step ${i + 1} title`} className="flex-1 border border-line-strong bg-ink-900 px-2 py-1 font-mono-ui text-[10px] text-paper outline-none" />
                <button type="button" onClick={() => setForm({ ...form, steps: form.steps.filter((_, j) => j !== i) })} className="text-red font-mono-ui text-[10px]">x</button>
              </div>
            ))}
            <button type="button" onClick={() => setForm({ ...form, steps: [...form.steps, { type: 'manual', title: '', description: '' }] })} className="font-mono-ui text-[10px] text-amber">+ Add step</button>
          </div>
          <button type="button" onClick={handleSubmit} className="w-full bg-amber/20 border border-amber/40 py-2 font-mono-ui text-[10px] text-amber hover:bg-amber/30">{editing ? 'Update Playbook' : 'Create Playbook'}</button>
        </div>
      )}

      {execution && (
        <div className="border-b border-line p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="font-mono-ui text-[10px] text-amber">EXECUTION // {execution.status?.toUpperCase()}</div>
            <button type="button" onClick={closeExecution} className="font-mono-ui text-[10px] text-ash-dark hover:text-red">Close</button>
          </div>
          {execution.alert_id && <div className="font-mono-ui text-[9px] text-ash-dark">Alert: {execution.alert_id}</div>}
          <div className="space-y-2">
            {(execution.steps || []).map((step, i) => {
              const done = (execution.completed_steps || []).includes(i);
              const current = execution.current_step === i;
              return (
                <div key={i} className={`flex items-center justify-between gap-2 border px-3 py-2 ${done ? 'border-green/30 bg-green/5' : current ? 'border-amber/40 bg-amber/5' : 'border-line-strong'}`}>
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`font-mono-ui text-[9px] ${done ? 'text-green' : current ? 'text-amber' : 'text-ash-dark'}`}>{done ? '✓' : current ? '►' : '○'}</span>
                    <span className={`px-1 py-0.5 font-mono-ui text-[9px] ${step.type === 'auto' ? 'bg-green/10 text-green' : step.type === 'approval' ? 'bg-cyan/10 text-cyan' : 'bg-blue/10 text-blue'}`}>{step.type}</span>
                    <span className="font-mono-ui text-[10px] text-paper truncate">{step.title || step.label || 'Untitled'}</span>
                  </div>
                  {!done && current && (
                    <button type="button" onClick={() => handleCompleteStep(execution.id, i)} className="shrink-0 bg-amber/20 border border-amber/40 px-2 py-1 font-mono-ui text-[9px] text-amber hover:bg-amber/30">Complete</button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="divide-y divide-line">
        {loading ? (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading...</div>
        ) : playbooks.length === 0 ? (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">No playbooks yet.</div>
        ) : (
          playbooks.map((pb) => (
            <div key={pb.id} className="px-4 py-4">
              <div className="flex items-center justify-between">
                <div className="min-w-0 flex-1">
                  <div className="font-mono-ui text-xs text-paper">{pb.name}</div>
                  <div className="mt-1 font-mono-ui text-[10px] text-ash-dark">{pb.description || 'No description'}</div>
                  <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 font-mono-ui text-[9px] text-amber">
                    <span>{pb.execution_count} executions</span>
                    <span>{pb.steps?.length || 0} steps</span>
                    {pb.alert_type && <span>type:{pb.alert_type}</span>}
                    {pb.severity_threshold && <span>min:{pb.severity_threshold}</span>}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <StatusDot tone={pb.is_enabled ? 'live' : 'offline'} />
                </div>
              </div>
              {pb.steps && pb.steps.length > 0 && (
                <div className="mt-3 space-y-1">
                  {pb.steps.map((step, i) => (
                    <div key={i} className="flex items-center gap-2 font-mono-ui text-[9px] text-ash-dark">
                      <span className="text-amber">{i + 1}.</span>
                      <span className={`px-1 py-0.5 ${step.type === 'auto' ? 'bg-green/10 text-green' : step.type === 'approval' ? 'bg-cyan/10 text-cyan' : 'bg-blue/10 text-blue'}`}>{step.type}</span>
                      <span className="truncate">{step.title || step.label || 'Untitled step'}</span>
                    </div>
                  ))}
                </div>
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                <button type="button" onClick={() => handleExecute(pb)} disabled={busy} className="bg-amber/20 border border-amber/40 px-2 py-1 font-mono-ui text-[9px] text-amber hover:bg-amber/30 disabled:opacity-50">Execute</button>
                <button type="button" onClick={() => openEdit(pb)} className="border border-line-strong px-2 py-1 font-mono-ui text-[9px] text-paper hover:border-amber/40">Edit</button>
                <button type="button" onClick={() => handleDelete(pb.id)} className="border border-line-strong px-2 py-1 font-mono-ui text-[9px] text-red hover:border-red/40">Delete</button>
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function NotificationsPanel() {
  const [prefs, setPrefs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [channel, setChannel] = useState('email');
  const [eventType, setEventType] = useState('alert.high_severity');

  const fetchPrefs = () => {
    const token = localStorage.getItem('flare_token');
    fetch(`${API_BASE}/api/v1/notifications/preferences`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => { setPrefs(d.preferences || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchPrefs(); }, []);

  const handleToggle = async (pref) => {
    const token = localStorage.getItem('flare_token');
    await fetch(`${API_BASE}/api/v1/notifications/preferences`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ channel: pref.channel, event_type: pref.event_type, is_enabled: !pref.is_enabled }),
    });
    fetchPrefs();
  };

  const handleAdd = async () => {
    const token = localStorage.getItem('flare_token');
    await fetch(`${API_BASE}/api/v1/notifications/preferences`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ channel, event_type: eventType, is_enabled: true }),
    });
    fetchPrefs();
  };

  const handleDelete = async (id) => {
    const token = localStorage.getItem('flare_token');
    await fetch(`${API_BASE}/api/v1/notifications/preferences/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
    fetchPrefs();
  };

  return (
    <section className="dashboard-panel">
      <div className="border-b border-line-strong px-4 py-4">
        <div className="eyebrow text-ash-dark">Alert notifications</div>
        <h2 className="mt-1 text-base font-semibold text-paper">Notification preferences</h2>
      </div>

      <div className="border-b border-line p-4">
        <div className="flex gap-2">
          <select value={channel} onChange={(e) => setChannel(e.target.value)} className="border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper">
            <option value="email">Email</option>
            <option value="slack">Slack</option>
          </select>
          <select value={eventType} onChange={(e) => setEventType(e.target.value)} className="flex-1 border border-line-strong bg-ink-900 px-2 py-2 font-mono-ui text-[10px] text-paper">
            <option value="alert.high_severity">High Severity Alert</option>
            <option value="rule.matched">Rule Matched</option>
            <option value="export.ready">Export Ready</option>
          </select>
          <button type="button" onClick={handleAdd} className="bg-amber/20 border border-amber/40 px-3 py-2 font-mono-ui text-[10px] text-amber hover:bg-amber/30">Add</button>
        </div>
      </div>

      <div className="divide-y divide-line">
        {loading ? (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">Loading...</div>
        ) : prefs.length === 0 ? (
          <div className="px-4 py-8 text-center font-mono-ui text-[10px] text-ash-dark">No notification preferences configured.</div>
        ) : (
          prefs.map((pref) => (
            <div key={pref.id} className="flex items-center justify-between px-4 py-4">
              <div className="flex items-center gap-3">
                <StatusDot tone={pref.is_enabled ? 'live' : 'offline'} />
                <div>
                  <div className="font-mono-ui text-xs text-paper">{pref.channel.toUpperCase()}</div>
                  <div className="mt-1 font-mono-ui text-[10px] text-ash-dark">{pref.event_type}</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button type="button" onClick={() => handleToggle(pref)} className="font-mono-ui text-[10px] text-amber hover:text-amber/80">
                  {pref.is_enabled ? 'Disable' : 'Enable'}
                </button>
                <button type="button" onClick={() => handleDelete(pref.id)} className="font-mono-ui text-[10px] text-red hover:text-red/80">Delete</button>
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

export default function WorkspacePanel({ section, alerts, filteredAlerts, selected, onSelect, filters, onFilterChange, density, onDensityChange, onAddAlert }) {
  if (section === 'overview' || section === 'feed') {
    return (
      <section className="dashboard-panel min-w-0">
        <div className="flex items-center justify-between border-b border-line-strong px-4 py-3">
          <div>
            <div className="eyebrow text-ash-dark">Priority queue // {String(filteredAlerts.length).padStart(3, '0')} visible</div>
            <h2 className="mt-1 text-base font-semibold text-paper">Live alert feed</h2>
          </div>
          <div className="hidden items-center gap-4 font-mono-ui text-[9px] uppercase tracking-[0.08em] text-ash-dark sm:flex">
            <span><span className="text-amber">J/K</span> navigate</span>
            <span><span className="text-amber">ENTER</span> inspect</span>
          </div>
        </div>
        <FilterStrip
          filters={filters}
          onFilterChange={onFilterChange}
          resultCount={filteredAlerts.length}
          density={density}
          onDensityChange={onDensityChange}
          onAddAlert={onAddAlert}
          onClear={() => onFilterChange({ search: undefined, severity: undefined, attack_type: undefined })}
        />
        <AlertTable
          alerts={filteredAlerts}
          selected={selected}
          onSelect={onSelect}
          density={density}
          query={filters.search || filters.severity || filters.attack_type ? 'active filters' : ''}
          onClear={() => onFilterChange({ search: undefined, severity: undefined, attack_type: undefined })}
        />
      </section>
    );
  }
  if (section === 'health') return <HealthPanel />;
  if (section === 'timeline') return <TimelinePanel />;
  if (section === 'audit-logs') return <AuditLogsPanel />;
  if (section === 'correlated') return <CorrelatedPanel onFilterChange={onFilterChange} />;
  if (section === 'eval') return <EvalPanel />;
  if (section === 'rules') return <RulesPanel />;
  if (section === 'playbooks') return <PlaybooksPanel selected={selected} />;
  if (section === 'notifications') return <NotificationsPanel />;
  if (section === 'export') return <ExportPanel filters={filters} />;
  return null;
}
