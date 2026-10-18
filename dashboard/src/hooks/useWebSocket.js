import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';
const WS_URL = (() => {
  if (typeof window === 'undefined') return 'ws://localhost:8000/ws/live-events';
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/ws/live-events`;
})();
const LIVE_EVENT_CAP = 500;
const SESSION_CAP = 200;
const POLL_MS = 20000;

const normalizeSession = (s) => ({
  ...s,
  techniques_detail: s.techniques_detail || [],
  techniques: s.techniques || [],
});

let _onAuthError = null;
export function setOnAuthError(cb) { _onAuthError = cb; }

export const api = axios.create({ baseURL: API_BASE });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      if (_onAuthError) _onAuthError();
    }
    return Promise.reject(error);
  }
);

function eventKey(e) {
  return `${e.session_id}|${e.timestamp}|${e.event_type}|${e.message}`;
}

export function useLiveData(enabled = true) {
  const [sessions, setSessions] = useState([]);
  const [liveEvents, setLiveEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [loadError, setLoadError] = useState('');
  const keysRef = useRef(new Set());

  const applySession = useCallback((session) => {
    const normalized = normalizeSession(session);
    setSessions((prev) => {
      const idx = prev.findIndex((s) => s.id === normalized.id);
      if (idx !== -1) {
        const next = [...prev];
        next[idx] = { ...next[idx], ...normalized };
        return next;
      }
      const next = [normalized, ...prev];
      return next.length > SESSION_CAP ? next.slice(0, SESSION_CAP) : next;
    });
  }, []);

  const pushEvents = useCallback((incoming) => {
    const list = Array.isArray(incoming) ? incoming : [incoming];
    setLiveEvents((prev) => {
      const next = [...prev];
      for (const e of list) {
        const k = eventKey(e);
        if (keysRef.current.has(k)) continue;
        keysRef.current.add(k);
        next.push(e);
      }
      if (next.length <= LIVE_EVENT_CAP) return next;
      const trimmed = next.slice(next.length - LIVE_EVENT_CAP);
      keysRef.current = new Set(trimmed.map(eventKey));
      return trimmed;
    });
  }, []);

  const hydrate = useCallback(async () => {
    const [sessRes, evtRes] = await Promise.all([
      api.get('/sessions'),
      api.get('/events', { params: { limit: LIVE_EVENT_CAP } }),
    ]);
    setSessions(sessRes.data.map(normalizeSession));
    keysRef.current = new Set();
    setLiveEvents([]);
    pushEvents(evtRes.data || []);
    setLoadError('');
    setLoading(false);
  }, [pushEvents]);

  useEffect(() => {
    if (!enabled) return;

    let ws;
    let closed = false;
    let retryMs = 1000;
    let retryTimer = null;
    let pollTimer = null;

    const connect = async () => {
      const token = localStorage.getItem('token');
      if (!token) return;

      try {
        await api.get('/api/v1/auth/me');
      } catch {
        localStorage.removeItem('token');
        if (_onAuthError) _onAuthError();
        return;
      }

      try {
        await hydrate();
      } catch (err) {
        setLoadError('Could not reach the API. Check that core-api is running.');
        setLoading(false);
      }

      ws = new WebSocket(`${WS_URL}?token=${token}`);

      ws.onopen = () => {
        retryMs = 1000;
        setConnected(true);
      };

      ws.onmessage = (event) => {
        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }

        if (msg.type === 'sessions') {
          setSessions(msg.data.map(normalizeSession));
          setLoading(false);
        } else if (msg.type === 'session') {
          applySession(msg.session);
        } else if (msg.type === 'event') {
          applySession(msg.session);
          pushEvents(msg.event);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        if (closed) return;
        retryTimer = setTimeout(connect, retryMs);
        retryMs = Math.min(retryMs * 2, 30000);
      };

      ws.onerror = () => ws.close();
    };

    connect();
    pollTimer = setInterval(() => {
      if (closed) return;
      api.get('/sessions')
        .then((res) => setSessions(res.data.map(normalizeSession)))
        .catch(() => {});
    }, POLL_MS);

    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      if (pollTimer) clearInterval(pollTimer);
      if (ws) ws.close();
    };
  }, [applySession, enabled, hydrate, pushEvents]);

  return { sessions, liveEvents, loading, connected, loadError };
}

/** @deprecated use useLiveData */
export const useWebSocket = useLiveData;
