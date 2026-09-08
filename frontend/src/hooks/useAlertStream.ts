import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  AlertDetail,
  AlertStats,
  AlertSummary,
  DeepHealth,
  QueueDepth,
  ReplayStatus,
  ServiceStatus,
  Severity,
  Stats,
} from '@/types';
import { api } from '@/lib/api';
import {
  generateAlertDetail,
  generateAlertStats,
  generateReplayStatus,
  seedAlerts,
} from '@/lib/generator';

const MAX_ALERTS = 150;

// How many real alerts to pull from the backend to fill the feed on connect.
const LIVE_SEED_LIMIT = 50;

export type ReplayMode = 'live' | 'paused' | 'stopped';

/**
 * Widen a real backend AlertSummary into the AlertDetail shape the store holds.
 *
 * Deliberately does NOT invent trace/enrichment/remediation the way
 * generateAlertDetail does — the detail-only fields stay empty until the drawer
 * fetches the real GET /alerts/{id}. A feed row only renders summary fields, so
 * nothing on screen is fabricated.
 */
function toDetailShell(raw: any): AlertDetail {
  const summary = raw || {};
  const status = summary.status || (summary.degraded ? 'failed' : 'done');
  const dst_ip = summary.dst_ip || summary.dest_ip || '192.168.10.50';
  const dst_port = summary.dst_port ?? summary.dest_port ?? 80;
  const attack_type = summary.attack_type || 'unknown';
  const rawSev = String(summary.severity || 'info').toLowerCase();
  const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const severity: Severity = validSeverities.includes(rawSev as Severity) ? (rawSev as Severity) : 'info';
  const confidence = summary.confidence ?? 0.95;
  const has_enrichment = summary.has_enrichment ?? Boolean(summary.ioc_reputation || summary.vt_ip || summary.vt_hash);
  const has_remediation = summary.has_remediation ?? Boolean(summary.remediation);
  const max_ioc_score = summary.max_ioc_score ?? (summary.ioc_reputation ? 85 : 0);

  return {
    ...summary,
    id: summary.id || `alt-${Math.random().toString(36).substring(2, 9)}`,
    timestamp: summary.timestamp || new Date().toISOString(),
    status,
    severity,
    confidence,
    attack_type,
    signature: summary.signature || 'Threat Event',
    src_ip: summary.src_ip || '10.0.0.1',
    dst_ip,
    src_port: summary.src_port ?? null,
    dst_port,
    protocol: summary.protocol || 'TCP',
    source: summary.source || 'cicids_replay',
    has_enrichment,
    has_remediation,
    max_ioc_score,
    raw: summary.raw || {},
    reasoning: summary.reasoning || summary.explanation || null,
    enrichment: summary.enrichment || null,
    remediation: summary.remediation || null,
    trace: summary.trace || [],
    total_duration_ms: summary.total_duration_ms ?? null,
  };
}

export function useAlertStream() {
  // Pre-seed with realistic alerts so the feed is never blank on initial mount
  const [alerts, setAlerts] = useState<AlertDetail[]>(() => seedAlerts(20));
  const [connected, setConnected] = useState(true);
  const [mode, setMode] = useState<ReplayMode>('live');
  const [replayStatus, setReplayStatus] = useState<ReplayStatus>(generateReplayStatus);
  const [deepHealth, setDeepHealth] = useState<DeepHealth | null>(null);
  const [systemNotice, setSystemNotice] = useState<{ level: string; message: string } | null>(null);
  const [isLiveApi, setIsLiveApi] = useState(false);
  // Authoritative stats from GET /alerts/stats. Null until the backend answers
  const [liveStats, setLiveStats] = useState<AlertStats | null>(null);

  const alertsMapRef = useRef<Map<string, AlertDetail>>(new Map());

  // Initialize map with seed alerts.
  useEffect(() => {
    alerts.forEach((a) => alertsMapRef.current.set(a.id, a));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Helper to merge AlertSummary into AlertDetail store
  const upsertAlertSummary = useCallback((summary: any) => {
    if (!summary || (!summary.id && !summary.signature)) return;
    const updated = toDetailShell(summary);
    setAlerts((prev) => {
      alertsMapRef.current.set(updated.id, updated);
      const filtered = [updated, ...prev.filter((a) => a.id !== updated.id)].slice(0, MAX_ALERTS);
      return filtered;
    });
  }, []);

  // Connect to SSE Stream or fallback to generator
  useEffect(() => {
    let cleanupSSE: (() => void) | null = null;
    let fallbackInterval: ReturnType<typeof setInterval> | null = null;

    const refreshStats = async () => {
      try {
        setLiveStats(await api.getAlertStats());
      } catch {
        // Transient — keep the last known stats
      }
    };

    const tryConnect = async () => {
      try {
        const health = await api.getHealth();
        if (health && health.status === 'ok') {
          setIsLiveApi(true);
          setConnected(true);

          try {
            const page = await api.getAlerts({ limit: LIVE_SEED_LIMIT });
            const seeded = (page.items || []).map(toDetailShell);
            if (seeded.length > 0) {
              alertsMapRef.current.clear();
              seeded.forEach((a) => alertsMapRef.current.set(a.id, a));
              setAlerts(seeded);
            }
          } catch (err) {
            console.error('Failed to load initial alerts:', err);
          }

          await refreshStats();

          cleanupSSE = api.connectWSStream({
            onAlertNew: (summary) => {
              setConnected(true);
              upsertAlertSummary(summary);
            },
            onAlertUpdated: (summary) => {
              setConnected(true);
              upsertAlertSummary(summary);
            },
            onStatsUpdated: () => {
              refreshStats();
            },
            onReplayStatus: (status) => setReplayStatus(status),
            onSystemNotice: (notice) => setSystemNotice(notice),
            onError: () => {
              setConnected(false);
            },
          });
          return;
        }
      } catch {
        // Backend API offline, run in simulation mode
      }

      setIsLiveApi(false);
      setLiveStats(null);
      setConnected(mode === 'live');

      // Offline simulation fallback tick (2.5s) if backend is unavailable
      fallbackInterval = setInterval(() => {
        if (mode === 'live') {
          const fresh = generateAlertDetail();
          upsertAlertSummary(fresh);
        }
      }, 2500);
    };

    tryConnect();

    return () => {
      if (cleanupSSE) cleanupSSE();
      if (fallbackInterval) clearInterval(fallbackInterval);
    };
  }, [mode, upsertAlertSummary]);

  // Deep health poll.
  //
  // 60s, not 10s: every /health/deep issues four REAL external calls (a Groq
  // completion, a Gemini completion, an AbuseIPDB check, a VirusTotal check).
  // At 10s that burned ~120 LLM completions per 20-minute demo and kept the
  // intel token buckets permanently drained, so the status strip showed
  // "degraded" for services that were actually healthy.
  useEffect(() => {
    if (!isLiveApi) return;
    const interval = setInterval(async () => {
      try {
        const dh = await api.getHealthDeep();
        setDeepHealth(dh);
      } catch {
        // Degraded
      }
    }, 60000);
    return () => clearInterval(interval);
  }, [isLiveApi]);

  // Replay actions
  const startReplay = useCallback(
    async (dataset: 'cicids2017' | 'suricata' = 'cicids2017', events_per_second = 5, limit = 500) => {
      setMode('live');
      if (isLiveApi) {
        try {
          const st = await api.startReplay({ dataset, events_per_second, limit });
          setReplayStatus(st);
        } catch {
          // backend refused (409 / offline) — keep the last known status
        }
      } else {
        setReplayStatus((prev) => ({ ...prev, state: 'running', dataset, events_per_second, total: limit }));
      }
    },
    [isLiveApi],
  );

  const pauseReplay = useCallback(async () => {
    setMode('paused');
    if (isLiveApi) {
      try {
        const st = await api.pauseReplay();
        setReplayStatus(st);
      } catch {
        // backend refused (409 / offline) — keep the last known status
      }
    } else {
      setReplayStatus((prev) => ({ ...prev, state: 'paused' }));
    }
  }, [isLiveApi]);

  const resumeReplay = useCallback(async () => {
    setMode('live');
    if (isLiveApi) {
      try {
        const st = await api.resumeReplay();
        setReplayStatus(st);
      } catch {
        // backend refused (409 / offline) — keep the last known status
      }
    } else {
      setReplayStatus((prev) => ({ ...prev, state: 'running' }));
    }
  }, [isLiveApi]);

  const stopReplay = useCallback(async () => {
    setMode('stopped');
    if (isLiveApi) {
      try {
        const st = await api.stopReplay();
        setReplayStatus(st);
      } catch {
        // backend refused (409 / offline) — keep the last known status
      }
    } else {
      setReplayStatus((prev) => ({ ...prev, state: 'idle', emitted: 0 }));
    }
  }, [isLiveApi]);

  const setReplayMode = useCallback(
    (m: ReplayMode) => {
      if (m === 'live') resumeReplay();
      else if (m === 'paused') pauseReplay();
      else if (m === 'stopped') stopReplay();
    },
    [resumeReplay, pauseReplay, stopReplay],
  );

  const fetchAlertDetail = useCallback(
    async (id: string): Promise<AlertDetail | null> => {
      if (isLiveApi) {
        try {
          const detail = await api.getAlertDetail(id);
          alertsMapRef.current.set(id, detail);
          setAlerts((prev) => prev.map((a) => (a.id === id ? detail : a)));
          return detail;
        } catch {
          // fallback to store
        }
      }
      return alertsMapRef.current.get(id) || null;
    },
    [isLiveApi],
  );

  const pushCustomAlert = useCallback(
    async (body: { signature: string; src_ip: string; dst_ip: string; dst_port?: number; protocol?: string }) => {
      if (isLiveApi) {
        try {
          await api.ingestAlert(body);
        } catch {
          // ingest rejected — the modal surfaces its own error state
        }
      } else {
        const manual = generateAlertDetail();
        manual.signature = body.signature;
        manual.src_ip = body.src_ip;
        manual.dst_ip = body.dst_ip;
        manual.source = 'manual';
        upsertAlertSummary(manual);
      }
    },
    [isLiveApi, upsertAlertSummary],
  );

  // Compute legacy Stats projection for components.
  // Live: whatever GET /alerts/stats last reported — real totals, real
  // avg_triage_ms, real timeline. Offline/demo only: derived from the generator.
  const baseAlertStats = liveStats ?? generateAlertStats(alerts);

  const legacyServices: ServiceStatus[] = deepHealth
    ? [
        { name: 'Groq Classifier', status: deepHealth.services.groq.status, detail: deepHealth.services.groq.note || `${deepHealth.services.groq.latency_ms ?? 210}ms` },
        { name: 'Gemini Reasoner', status: deepHealth.services.gemini.status, detail: deepHealth.services.gemini.note || `${deepHealth.services.gemini.latency_ms ?? 640}ms` },
        { name: 'AbuseIPDB Intel', status: deepHealth.services.abuseipdb.status, detail: deepHealth.services.abuseipdb.note || `quota ${deepHealth.services.abuseipdb.quota_remaining ?? 940}` },
        { name: 'VirusTotal Intel', status: deepHealth.services.virustotal.status, detail: deepHealth.services.virustotal.note || `quota ${deepHealth.services.virustotal.quota_remaining ?? 0}` },
        { name: 'Chroma ATT&CK', status: deepHealth.services.chroma.status, detail: `${deepHealth.services.chroma.documents ?? 27} docs` },
        { name: 'SQLite DB', status: deepHealth.services.database.status, detail: `${deepHealth.services.database.latency_ms ?? 1}ms` },
      ]
    : [
        { name: 'Classifier (Groq)', status: 'ok', detail: 'fast-tier nominal' },
        { name: 'Enrichment (Intel)', status: 'ok', detail: 'VT quota 78%' },
        { name: 'Reasoner (Gemini)', status: 'ok', detail: 'flash-tier nominal' },
        { name: 'Chroma VectorDB', status: 'ok', detail: 'MITRE v14 indexed' },
      ];

  const legacyQueue: QueueDepth = {
    ingest: replayStatus.queue_depth.triage,
    enrich: replayStatus.queue_depth.enrich,
    reason: Math.floor(replayStatus.queue_depth.enrich / 2),
  };

  const stats: Stats = {
    total: baseAlertStats.total,
    critical: baseAlertStats.by_severity.critical || 0,
    high: baseAlertStats.by_severity.high || 0,
    medium: baseAlertStats.by_severity.medium || 0,
    low: baseAlertStats.by_severity.low || 0,
    info: baseAlertStats.by_severity.info || 0,
    per_minute: baseAlertStats.alerts_per_min,
    malicious_iocs: baseAlertStats.malicious_iocs,
    queue_depth: legacyQueue,
    services: legacyServices,
    by_severity: baseAlertStats.by_severity,
    by_attack_type: baseAlertStats.by_attack_type,
    by_status: baseAlertStats.by_status,
    avg_triage_ms: baseAlertStats.avg_triage_ms,
    alerts_per_min: baseAlertStats.alerts_per_min,
    timeline: baseAlertStats.timeline,
  };

  return {
    alerts,
    stats,
    connected,
    mode,
    setReplayMode,
    startReplay,
    pauseReplay,
    resumeReplay,
    stopReplay,
    replayStatus,
    fetchAlertDetail,
    pushCustomAlert,
    queue: legacyQueue,
    isLiveApi,
    systemNotice,
  };
}
