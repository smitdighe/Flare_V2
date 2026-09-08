import type {
  AlertDetail,
  AlertStats,
  AlertSummary,
  BenchmarkReport,
  DeepHealth,
  EvalReport,
  ReplayStatus,
} from '@/types';

// The rest of the app reads VITE_API_BASE; keep VITE_API_BASE_URL as a fallback.
const BASE_URL =
  (import.meta.env.VITE_API_BASE as string | undefined) ||
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ||
  '';
const API_PREFIX = '/api/v1';

const TOKEN_KEYS = ['flare_token', 'flare_jwt'];
const REFRESH_KEYS = ['flare_refresh', 'flare_refresh_token'];

// ── envelope contract ────────────────────────────────────────────────────────
// Backend default response shape is { ok, data, meta:{latency_ms} } (CONTRACT §1.3).
// A closed list of 11 operations returns a RAW body — those callers pass
// `raw: true` and read the body as-is.
function unwrap<T = any>(body: any): T {
  if (
    body &&
    typeof body === 'object' &&
    'ok' in body &&
    'data' in body
  ) {
    return body.data as T;
  }
  return body as T;
}

export class ApiError extends Error {
  code: string;
  status: number;
  detail: unknown;

  constructor(code: string, message: string, status: number, detail: unknown = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

export function isJwtValid(token: string | null): boolean {
  if (!token || typeof token !== 'string') return false;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const jsonStr = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    const payload = JSON.parse(jsonStr);
    if (!payload.exp) return true;
    return payload.exp * 1000 > Date.now() + 15000;
  } catch {
    return false;
  }
}

function readToken(): string | null {
  for (const k of TOKEN_KEYS) {
    const v = localStorage.getItem(k);
    if (v) return v;
  }
  return null;
}

function readRefresh(): string | null {
  for (const k of REFRESH_KEYS) {
    const v = localStorage.getItem(k);
    if (v) return v;
  }
  return null;
}

function storeTokens(access?: string | null, refresh?: string | null): void {
  if (access) {
    localStorage.setItem('flare_token', access);
    localStorage.setItem('flare_jwt', access);
  }
  if (refresh) {
    localStorage.setItem('flare_refresh', refresh);
  }
}

function clearTokens(): void {
  [...TOKEN_KEYS, ...REFRESH_KEYS].forEach((k) => localStorage.removeItem(k));
}

// Exchange the stored refresh token for a fresh access token. Returns '' on failure.
async function refreshAccessToken(): Promise<string> {
  const refresh_token = readRefresh();
  if (!refresh_token) return '';
  try {
    const res = await fetch(`${BASE_URL}${API_PREFIX}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token }),
    });
    if (!res.ok) return '';
    const data = await res.json(); // raw — pinned exception #3
    storeTokens(data.access_token, data.refresh_token);
    return data.access_token || '';
  } catch {
    return '';
  }
}

export async function getValidToken(): Promise<string> {
  const token = readToken();
  if (token && isJwtValid(token)) return token;
  return (await refreshAccessToken()) || token || '';
}

interface RequestOptions extends RequestInit {
  raw?: boolean; // do not unwrap the envelope (pinned exceptions)
  blob?: boolean; // return a Blob
  auth?: boolean; // send Authorization header (default true, except /auth/login|register|refresh)
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const url = `${BASE_URL}${API_PREFIX}${path}`;
  const isAuthRoute = path.startsWith('/auth/login') || path.startsWith('/auth/register') || path.startsWith('/auth/refresh');
  const wantAuth = options.auth ?? !isAuthRoute;

  let token = wantAuth ? readToken() : null;
  if (wantAuth && (!token || !isJwtValid(token))) {
    token = await getValidToken();
  }

  const doFetch = (bearer?: string | null) =>
    fetch(url, {
      ...options,
      headers: {
        ...(options.body && !options.blob ? { 'Content-Type': 'application/json' } : {}),
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
        ...options.headers,
      },
    });

  let response = await doFetch(token);

  // One silent refresh + retry on 401 (not for the auth routes themselves).
  if (response.status === 401 && wantAuth && !isAuthRoute) {
    clearTokens();
    const fresh = await refreshAccessToken();
    if (fresh) response = await doFetch(fresh);
  }

  if (!response.ok) {
    let code = 'internal_error';
    let message = `Request failed with status ${response.status}`;
    let detail: unknown = null;
    try {
      const data = await response.json();
      // Backend error body: { ok:false, detail, error:{code,message,detail} }
      code = data?.error?.code || code;
      message = data?.error?.message || data?.detail || (typeof data?.detail === 'string' ? data.detail : message);
      detail = data?.error?.detail ?? data?.detail ?? null;
    } catch {
      // non-JSON body
    }
    throw new ApiError(code, message, response.status, detail);
  }

  if (response.status === 204) return undefined as T;
  if (options.blob) return (await response.blob()) as T;

  const body = await response.json();
  return options.raw ? (body as T) : (unwrap<T>(body));
}

// ── param helpers ────────────────────────────────────────────────────────────
function qs(params?: Record<string, unknown>): string {
  if (!params) return '';
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
  });
  const s = q.toString();
  return s ? `?${s}` : '';
}

// ── request/response param types ─────────────────────────────────────────────
export interface GetAlertsParams {
  limit?: number;
  offset?: number;
  severity?: string;
  attack_type?: string;
  search?: string;
  // accepted by the client, ignored by the real backend list route:
  status?: string;
  src_ip?: string;
  malicious_only?: boolean;
  since?: string;
  sort?: string;
}

export interface GetAlertsResponse {
  items: AlertSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface IngestAlertParams {
  signature: string;
  src_ip: string;
  dst_ip: string;
  dst_port?: number;
  protocol?: string;
  event_type?: string;
  [key: string]: unknown;
}

export interface IngestResponse {
  accepted: number;
  dropped: number;
  alert_ids?: string[];
}

export interface StartReplayParams {
  dataset?: string;
  events_per_second?: number;
  limit?: number;
}

export interface AuditParams {
  limit?: number;
  offset?: number;
  action?: string;
  resource_type?: string;
}

// ── the client ───────────────────────────────────────────────────────────────
export const api = {
  // ── Auth (pinned raw: login, register, refresh, me) ──────────────────────
  login: async (body: { email: string; password: string }) => {
    const data = await request<{ access_token: string; refresh_token: string; user: any }>(
      '/auth/login',
      { method: 'POST', body: JSON.stringify(body), raw: true, auth: false }
    );
    storeTokens(data.access_token, data.refresh_token);
    return data;
  },
  register: async (body: { email: string; name: string; password: string }) => {
    const data = await request<{ access_token: string; refresh_token: string; user: any }>(
      '/auth/register',
      { method: 'POST', body: JSON.stringify(body), raw: true, auth: false }
    );
    storeTokens(data.access_token, data.refresh_token);
    return data;
  },
  refresh: async () => {
    const refresh_token = readRefresh();
    const data = await request<{ access_token: string; refresh_token: string }>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token }),
      raw: true,
      auth: false,
    });
    storeTokens(data.access_token, data.refresh_token);
    return data;
  },
  me: () => request<any>('/auth/me', { raw: true }),
  updateProfile: (body: { name: string; email: string }) =>
    request<any>('/auth/profile', { method: 'PUT', body: JSON.stringify(body) }),
  changePassword: (body: { current_password: string; new_password: string }) =>
    request<any>('/auth/change-password', { method: 'POST', body: JSON.stringify(body) }),
  logout: () => clearTokens(),

  // ── Health & stats ──────────────────────────────────────────────────────
  // Real /health returns { services:[{name,status,latency_ms,message}] } with no
  // top-level status. Synthesize one (worst-wins) so callers can test
  // `health.status === 'ok'`.
  getHealth: async () => {
    const data = await request<any>('/health');
    const services = data?.services ?? [];
    const bad = services.some((s: any) => s?.status && s.status !== 'ok' && s.status !== 'rate_limited');
    const degraded = services.some((s: any) => s?.status === 'rate_limited');
    return { ...data, services, status: bad ? 'error' : degraded ? 'degraded' : 'ok' };
  },
  getHealthDeep: () => request<DeepHealth>('/health/deep'),
  getStats: () => request<any>('/stats'),

  // ── Alerts ──────────────────────────────────────────────────────────────
  getAlerts: async (params?: GetAlertsParams): Promise<GetAlertsResponse> => {
    const data = await request<any>(
      `/alerts${qs({
        limit: params?.limit,
        offset: params?.offset,
        severity: params?.severity,
        attack_type: params?.attack_type,
        search: params?.search ?? params?.src_ip,
      })}`
    );
    const items: AlertSummary[] = data?.alerts ?? data?.items ?? (Array.isArray(data) ? data : []);
    return {
      items: Array.isArray(items) ? items : [],
      total: data?.total ?? items?.length ?? 0,
      limit: data?.limit ?? params?.limit ?? 50,
      offset: data?.offset ?? params?.offset ?? 0,
    };
  },
  // No GET /alerts/{id} on the real backend — resolve via the list + search.
  getAlertDetail: async (id: string): Promise<AlertDetail> => {
    const data = await request<any>(`/alerts${qs({ search: id, limit: 1 })}`);
    const list: any[] = data?.alerts ?? data?.items ?? (Array.isArray(data) ? data : []);
    const hit = list.find((a) => a?.id === id) ?? list[0];
    if (!hit) throw new ApiError('not_found', `alert ${id} not found`, 404);
    return hit as AlertDetail;
  },
  getAttackTypes: () => request<any>('/alerts/attack-types'),
  getClusters: (params?: { min_alerts?: number; limit?: number }) =>
    request<any>(`/alerts/clusters${qs(params as Record<string, unknown>)}`),

  // Aggregate the two counter sources the header needs (CONTRACT §2.2 / §2.10).
  getAlertStats: async (params?: { severity?: string; attack_type?: string; search?: string }): Promise<AlertStats> => {
    const [statsData, overview] = await Promise.all([
      request<any>('/stats').catch(() => ({})),
      request<any>(`/metrics/overview${qs(params as Record<string, unknown>)}`).catch(() => ({})),
    ]);
    return {
      timeline: statsData?.timeline ?? [],
      alerts_per_min: statsData?.alert_velocity ?? statsData?.alerts_per_min ?? 0,
      total: overview?.total ?? statsData?.total ?? 0,
      by_severity: overview?.by_severity ?? {},
      by_attack_type: overview?.by_attack_type ?? {},
      by_status: overview?.by_status ?? {},
      malicious_iocs: overview?.malicious_iocs ?? 0,
      avg_triage_ms: overview?.avg_triage_ms ?? statsData?.avg_triage_ms ?? 0,
    } as AlertStats;
  },
  getMetricsOverview: (params?: { severity?: string; attack_type?: string; search?: string }) =>
    request<any>(`/metrics/overview${qs(params as Record<string, unknown>)}`),
  getMetricsRail: () => request<any>('/metrics/rail'),

  // ── Ingest ──────────────────────────────────────────────────────────────
  // The real backend accepts only Suricata EVE batches at POST /ingest/eve
  // (service-token auth). Adapt the simplified inject-modal shape into one EVE
  // record so the "try your own alert" button still functions.
  ingestAlert: (body: IngestAlertParams) => {
    const eve = {
      timestamp: new Date().toISOString(),
      event_type: 'alert',
      src_ip: body.src_ip,
      dest_ip: body.dst_ip,
      dest_port: body.dst_port,
      proto: body.protocol,
      alert: { signature: body.signature, category: body.event_type ?? 'manual', severity: 2 },
    };
    return request<IngestResponse>('/ingest/eve', {
      method: 'POST',
      body: JSON.stringify({ events: [eve] }),
    });
  },
  ingestEve: (events: unknown[]) =>
    request<IngestResponse>('/ingest/eve', { method: 'POST', body: JSON.stringify({ events }) }),

  // ── Evaluation (real backend: single cached report at GET /eval) ─────────
  runEvaluation: (_sampleSize?: number) => request<any>('/eval?force=true'),
  getEvaluation: () => request<any>('/eval'),
  getEvaluationRuns: async (): Promise<EvalReport[]> => {
    const r = await request<any>('/eval').catch(() => null);
    return r ? [r as EvalReport] : [];
  },
  getEvaluationRun: (_run_id?: string) => request<EvalReport>('/eval'),

  // ── Benchmark (no dedicated route — the fast/quality split lives in /eval.tiers) ─
  runBenchmark: (_sampleSize?: number) => request<any>('/eval?force=true'),
  getBenchmarkRuns: async (): Promise<BenchmarkReport[]> => {
    const r = await request<any>('/eval').catch(() => null);
    if (!r) return [];
    const tiers = r.tiers ?? r.per_tier ?? null;
    return [{ ...(r as any), results: tiers ?? [], run_id: r.run_id ?? 'eval', status: r.status ?? 'completed' }] as BenchmarkReport[];
  },
  getBenchmarkRun: (_run_id?: string) => request<BenchmarkReport>('/eval'),

  // ── Replay — no HTTP route; the live feed is the WebSocket. pause/resume are
  //    sent over the socket via connectWSStream()'s returned controls. ────────
  startReplay: async (_params?: StartReplayParams): Promise<ReplayStatus> => localReplay('running'),
  pauseReplay: async (): Promise<ReplayStatus> => localReplay('paused'),
  resumeReplay: async (): Promise<ReplayStatus> => localReplay('running'),
  stopReplay: async (): Promise<ReplayStatus> => localReplay('idle'),
  getReplayStatus: async (): Promise<ReplayStatus> => localReplay('running'),

  // ── Audit ───────────────────────────────────────────────────────────────
  getAuditLogs: async (params?: AuditParams) => {
    try {
      return await request<any>(`/audit/logs${qs(params as Record<string, unknown>)}`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        return request<any>(`/audit/logs/me${qs(params as Record<string, unknown>)}`);
      }
      throw e;
    }
  },
  getMyAuditLogs: (params?: AuditParams) =>
    request<any>(`/audit/logs/me${qs(params as Record<string, unknown>)}`),

  // ── Rules (list + explain-rules are pinned raw) ─────────────────────────
  getRules: async () => {
    const body = await request<any>('/rules', { raw: true });
    return body?.rules ?? [];
  },
  createRule: (body: unknown) => request<any>('/rules', { method: 'POST', body: JSON.stringify(body) }),
  deleteRule: (ruleId: number | string) => request<void>(`/rules/${ruleId}`, { method: 'DELETE' }),
  explainRules: (alertId: string) =>
    request<any>(`/rules/alerts/${alertId}/explain-rules`, { raw: true }),

  // ── Playbooks (list + execute + get-execution are pinned raw) ───────────
  getPlaybooks: async () => {
    const body = await request<any>('/playbooks', { raw: true });
    return body?.playbooks ?? [];
  },
  createPlaybook: (body: unknown) =>
    request<any>('/playbooks', { method: 'POST', body: JSON.stringify(body) }),
  updatePlaybook: (id: number | string, body: unknown) =>
    request<any>(`/playbooks/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  deletePlaybook: (id: number | string) =>
    request<void>(`/playbooks/${id}`, { method: 'DELETE' }),
  executePlaybook: (id: number | string, alertId?: string) =>
    request<{ execution_id: number | string }>(
      `/playbooks/${id}/execute${qs({ alert_id: alertId })}`,
      { method: 'POST', raw: true }
    ),
  getExecution: (executionId: number | string) =>
    request<any>(`/playbooks/executions/${executionId}`, { raw: true }),
  completeStep: (executionId: number | string, stepIndex: number, notes = '') =>
    request<void>(`/playbooks/executions/${executionId}/steps/${stepIndex}`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    }),

  // ── Notifications (preferences list is pinned raw) ──────────────────────
  getNotificationPrefs: async () => {
    const body = await request<any>('/notifications/preferences', { raw: true });
    return body?.preferences ?? [];
  },
  saveNotificationPref: (body: { channel: string; event_type: string; is_enabled: boolean }) =>
    request<any>('/notifications/preferences', { method: 'POST', body: JSON.stringify(body) }),
  deleteNotificationPref: (id: number | string) =>
    request<void>(`/notifications/preferences/${id}`, { method: 'DELETE' }),
  getNotificationLog: (params?: { limit?: number; offset?: number; outcome?: 'sent' | 'suppressed' | 'failed' }) =>
    request<any>(`/notifications/log${qs(params as Record<string, unknown>)}`),

  // ── Export (binary blob, pinned raw) ───────────────────────────────────
  exportAlerts: (
    format: 'csv' | 'pdf',
    params?: { severity?: string; attack_type?: string; search?: string; limit?: number }
  ) =>
    request<Blob>(`/export/alerts/${format}${qs({ limit: 500, ...(params ?? {}) })}`, { blob: true }),

  // ── Admin ──────────────────────────────────────────────────────────────
  getJobs: (limit = 25) => request<any>(`/admin/jobs${qs({ limit })}`),
  runJob: (job: string) => request<any>(`/admin/jobs/${job}/run`, { method: 'POST' }),

  // ── Live WebSocket stream ──────────────────────────────────────────────
  // GET /api/v1/ws/stream — no query string. First frame is the auth handshake
  // (CONTRACT §3). Server pushes one bare Alert object per message.
  connectWSStream: (handlers: {
    onAlertNew?: (alert: AlertSummary) => void;
    onAlertUpdated?: (alert: AlertSummary) => void;
    onStatsUpdated?: (stats: AlertStats) => void;
    onReplayStatus?: (status: ReplayStatus) => void;
    onSystemNotice?: (notice: { level: 'info' | 'warn' | 'error'; message: string }) => void;
    onOpen?: () => void;
    onClose?: (e: CloseEvent) => void;
    onError?: (err: Event) => void;
  }): (() => void) & {
    close: () => void;
    pause: () => void;
    resume: () => void;
    setSpeed: (speed: number) => void;
    setPresence: (state: 'active' | 'backgrounded') => void;
  } => {
    let ws: WebSocket | null = null;
    let disposed = false;
    let attempt = 0;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const send = (msg: unknown) => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
    };

    const connect = async () => {
      if (disposed) return;

      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      let host = window.location.host;
      if (BASE_URL && /^https?:\/\//.test(BASE_URL)) host = BASE_URL.replace(/^https?:\/\//, '');
      const url = `${proto}//${host}${API_PREFIX}/ws/stream`;

      const token = await getValidToken();
      if (disposed) return;

      ws = new WebSocket(url);

      ws.onopen = () => {
        attempt = 0;
        // First frame: auth, then presence (CONTRACT §3.0).
        send({ type: 'auth', token });
        send({ type: 'presence', state: document.visibilityState === 'visible' ? 'active' : 'backgrounded' });
        handlers.onOpen?.();
      };

      ws.onmessage = (e: MessageEvent) => {
        let data: any;
        try {
          data = JSON.parse(e.data);
        } catch {
          return; // malformed frame — drop
        }
        // Bare Alert object per CONTRACT §3.1.
        if (data && typeof data === 'object' && data.id) {
          handlers.onAlertNew?.(data);
          handlers.onAlertUpdated?.(data);
          return;
        }
        // Tolerate a few tagged control frames if the backend ever adds them.
        if (data?.type === 'stats.updated') handlers.onStatsUpdated?.(data.data ?? data);
        else if (data?.type === 'replay.status') handlers.onReplayStatus?.(data.data ?? data);
        else if (data?.type === 'system.notice') handlers.onSystemNotice?.(data.data ?? data);
      };

      ws.onerror = (ev) => handlers.onError?.(ev);

      ws.onclose = (ev: CloseEvent) => {
        handlers.onClose?.(ev);
        if (ev.code === 4001 || ev.code === 4003) {
          clearTokens();
          return; // auth failure — no reconnect
        }
        if (disposed || ev.code === 1000) return;
        const delay = Math.min(1000 * 2 ** attempt, 30000);
        attempt += 1;
        reconnectTimer = setTimeout(connect, delay);
      };
    };

    const onVisibility = () =>
      send({ type: 'presence', state: document.visibilityState === 'visible' ? 'active' : 'backgrounded' });
    document.addEventListener('visibilitychange', onVisibility);

    connect();

    const close = () => {
      disposed = true;
      document.removeEventListener('visibilitychange', onVisibility);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws && ws.readyState === WebSocket.OPEN) ws.close(1000, 'cleanup');
    };

    // Callable cleanup (legacy `cleanup()` style) with control methods attached.
    const handle = close as (() => void) & Record<string, unknown>;
    handle.close = close;
    handle.pause = () => send({ type: 'pause' });
    handle.resume = () => send({ type: 'resume' });
    handle.setSpeed = (speed: number) => send({ type: 'config', speed });
    handle.setPresence = (state: 'active' | 'backgrounded') => send({ type: 'presence', state });
    return handle as any;
  },
};

// Local-only replay status stand-in — the real backend has no replay HTTP route.
function localReplay(state: ReplayStatus['state']): ReplayStatus {
  return {
    state,
    dataset: 'cicids2017',
    events_per_second: 0,
    emitted: 0,
    total: null,
    queue_depth: { triage: 0, enrich: 0 },
    started_at: state === 'idle' ? null : new Date().toISOString(),
    skipped: 0,
  };
}

export default api;
