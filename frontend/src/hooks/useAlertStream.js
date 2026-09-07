import { useEffect, useRef, useCallback, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || '';
const WS_BASE = API_BASE.replace(/^http/, 'ws');

export function useAlertStream(token, { paused = false, onAlert } = {}) {
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const retryCountRef = useRef(0);
  const onAlertRef = useRef(onAlert);
  onAlertRef.current = onAlert;

  const connect = useCallback(() => {
    if (!token || paused) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setConnectionStatus('connecting');
    // FE-2: the token travels in the first frame, never in the query string —
    // URLs land in proxy logs and browser history, frames do not.
    const ws = new WebSocket(`${WS_BASE}/api/v1/ws/stream`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnectionStatus('connected');
      retryCountRef.current = 0;
      ws.send(JSON.stringify({ type: 'auth', token }));
      ws.send(JSON.stringify({
        type: 'presence',
        state: document.visibilityState === 'hidden' ? 'backgrounded' : 'active',
      }));
    };

    ws.onmessage = (event) => {
      try {
        const alert = JSON.parse(event.data);
        if (alert?.id) onAlertRef.current?.(alert);
      } catch { /* ignore malformed */ }
    };

    ws.onclose = (event) => {
      setConnectionStatus('disconnected');
      wsRef.current = null;
      if (event.code === 4001 || event.code === 4003) return; // auth error, don't retry
      // Exponential backoff reconnect
      const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 30000);
      retryCountRef.current++;
      reconnectTimerRef.current = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      setConnectionStatus('error');
    };
  }, [token, paused]);

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnect');
      wsRef.current = null;
    }
    setConnectionStatus('disconnected');
  }, []);

  const sendCommand = useCallback((cmd) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(cmd));
    }
  }, []);

  const pause = useCallback(() => sendCommand({ type: 'pause' }), [sendCommand]);
  const resume = useCallback(() => sendCommand({ type: 'resume' }), [sendCommand]);
  const setSpeed = useCallback((speed) => sendCommand({ type: 'config', speed }), [sendCommand]);

  useEffect(() => {
    connect();
    return disconnect;
  }, [connect, disconnect]);

  // FE-2: presence. The server debounces notifications for a user who is
  // watching the dashboard, so it has to be told when the tab goes away.
  useEffect(() => {
    const onVisibilityChange = () => {
      sendCommand({
        type: 'presence',
        state: document.visibilityState === 'hidden' ? 'backgrounded' : 'active',
      });
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [sendCommand]);

  return { connectionStatus, pause, resume, setSpeed, sendCommand };
}
