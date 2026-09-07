import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';

const AuthContext = createContext(null);

const API_BASE = import.meta.env.VITE_API_BASE || '';
const REFRESH_BUFFER_MS = 5 * 60 * 1000; // refresh 5 min before expiry

function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem('flare_token'));
  const [refreshToken, setRefreshToken] = useState(() => localStorage.getItem('flare_refresh'));
  const [loading, setLoading] = useState(true);
  const refreshTimerRef = useRef(null);

  const clearAuth = useCallback(() => {
    localStorage.removeItem('flare_token');
    localStorage.removeItem('flare_refresh');
    setToken(null);
    setRefreshToken(null);
    setUser(null);
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  const scheduleRefresh = useCallback((accessToken) => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    const payload = parseJwt(accessToken);
    if (!payload || !payload.exp) return;
    const expiresAt = payload.exp * 1000;
    const delay = Math.max(0, expiresAt - Date.now() - REFRESH_BUFFER_MS);
    refreshTimerRef.current = setTimeout(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: localStorage.getItem('flare_refresh') }),
        });
        if (!res.ok) throw new Error('Refresh failed');
        const data = await res.json();
        localStorage.setItem('flare_token', data.access_token);
        localStorage.setItem('flare_refresh', data.refresh_token);
        setToken(data.access_token);
        setRefreshToken(data.refresh_token);
        scheduleRefresh(data.access_token);
      } catch {
        clearAuth();
      }
    }, delay);
  }, [clearAuth]);

  const doRefreshToken = useCallback(async () => {
    const rt = localStorage.getItem('flare_refresh');
    if (!rt) { clearAuth(); return null; }
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!res.ok) throw new Error('Refresh failed');
      const data = await res.json();
      localStorage.setItem('flare_token', data.access_token);
      localStorage.setItem('flare_refresh', data.refresh_token);
      setToken(data.access_token);
      setRefreshToken(data.refresh_token);
      scheduleRefresh(data.access_token);
      return data.access_token;
    } catch {
      clearAuth();
      return null;
    }
  }, [clearAuth, scheduleRefresh]);

  useEffect(() => {
    if (token) {
      fetch(`${API_BASE}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((r) => {
          if (r.status === 401) return Promise.reject('expired');
          return r.ok ? r.json() : Promise.reject();
        })
        .then((data) => {
          setUser(data);
          setLoading(false);
          scheduleRefresh(token);
        })
        .catch(async (err) => {
          if (err === 'expired' && refreshToken) {
            const newToken = await doRefreshToken();
            if (newToken) {
              fetch(`${API_BASE}/api/v1/auth/me`, {
                headers: { Authorization: `Bearer ${newToken}` },
              })
                .then((r) => r.ok ? r.json() : Promise.reject())
                .then((data) => { setUser(data); setLoading(false); })
                .catch(() => { clearAuth(); setLoading(false); });
              return;
            }
          }
          clearAuth();
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const login = async (email, password) => {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) {
      let detail = 'Login failed';
      try {
        const err = await res.json();
        detail = err.detail || detail;
      } catch {
        throw new Error('Cannot reach the server — please try again later.');
      }
      throw new Error(detail);
    }
    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error('Invalid response from server.');
    }
    localStorage.setItem('flare_token', data.access_token);
    localStorage.setItem('flare_refresh', data.refresh_token);
    setToken(data.access_token);
    setRefreshToken(data.refresh_token);
    setUser(data.user);
    scheduleRefresh(data.access_token);
    return data;
  };

  const register = async (email, name, password) => {
    const res = await fetch(`${API_BASE}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, name, password }),
    });
    if (!res.ok) {
      let detail = 'Registration failed';
      try {
        const err = await res.json();
        detail = err.detail || detail;
      } catch {
        throw new Error('Cannot reach the server — please try again later.');
      }
      throw new Error(detail);
    }
    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error('Invalid response from server.');
    }
    localStorage.setItem('flare_token', data.access_token);
    localStorage.setItem('flare_refresh', data.refresh_token);
    setToken(data.access_token);
    setRefreshToken(data.refresh_token);
    setUser(data.user);
    scheduleRefresh(data.access_token);
    return data;
  };

  const logout = () => {
    clearAuth();
  };

  const getAuthHeaders = useCallback(() => {
    const t = localStorage.getItem('flare_token');
    return t ? { Authorization: `Bearer ${t}` } : {};
  }, []);

  const authFetch = useCallback(async (url, options = {}) => {
    const t = localStorage.getItem('flare_token');
    const headers = { ...options.headers, ...(t ? { Authorization: `Bearer ${t}` } : {}) };
    let res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      const newToken = await doRefreshToken();
      if (newToken) {
        headers.Authorization = `Bearer ${newToken}`;
        res = await fetch(url, { ...options, headers });
      }
    }
    return res;
  }, [doRefreshToken]);

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout, getAuthHeaders, authFetch }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
