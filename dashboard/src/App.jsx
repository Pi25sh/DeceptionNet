import { useState, useEffect, useRef } from 'react';
import { api, useLiveData, setOnAuthError } from './hooks/useWebSocket';
import LoginScreen from './components/LoginScreen';
import Header from './components/Header';
import TabNav from './components/TabNav';
import SessionList from './components/SessionList';
import SessionDetail from './components/SessionDetail';
import AnalyticsTab from './components/AnalyticsTab';
import ReportsTab from './components/ReportsTab';
import LiveFeedTab from './components/LiveFeedTab';

const LIVE_MERGE_FIELDS = [
  'severity_score', 'ai_summary', 'src_ip', 'start_time', 'end_time',
  'techniques', 'techniques_detail', 'honeypot',
];

function mergeEvents(existing, incoming) {
  const seen = new Set(existing.map((e) => `${e.timestamp}|${e.event_type}|${e.message}`));
  const extra = incoming.filter((e) => !seen.has(`${e.timestamp}|${e.event_type}|${e.message}`));
  if (extra.length === 0) return existing;
  return [...existing, ...extra].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [user, setUser] = useState(null);
  const [currentTab, setCurrentTab] = useState('sessions');
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetails, setSessionDetails] = useState(null);
  const [reportGenerating, setReportGenerating] = useState(false);
  const [reportsVersion, setReportsVersion] = useState(0);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);

  const showToast = (type, message, ms) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ type, message });
    toastTimer.current = setTimeout(() => {
      setToast(null);
      toastTimer.current = null;
    }, ms);
  };

  useEffect(() => {
    setOnAuthError(() => setAuthenticated(false));
  }, []);

  const { sessions, liveEvents, loading, connected, loadError } = useLiveData(authenticated);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      api.get('/api/v1/auth/me')
        .then((res) => {
          setUser(res.data);
          setAuthenticated(true);
        })
        .catch(() => {
          localStorage.removeItem('token');
          setAuthenticated(false);
        })
        .finally(() => setAuthChecked(true));
    } else {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    if (!selectedSession) { setSessionDetails(null); return; }
    api.get(`/sessions/${selectedSession}`)
      .then((res) => setSessionDetails(res.data))
      .catch((err) => console.error('Failed to fetch session details', err));
  }, [selectedSession]);

  useEffect(() => {
    if (!selectedSession) return;
    const live = sessions.find((s) => s.id === selectedSession);
    if (!live) return;
    setSessionDetails((prev) => {
      if (!prev) return prev;
      const merged = { ...prev };
      for (const key of LIVE_MERGE_FIELDS) {
        if (live[key] != null) merged[key] = live[key];
      }
      return merged;
    });
  }, [sessions, selectedSession]);

  useEffect(() => {
    if (!selectedSession) return;
    const incoming = liveEvents.filter((e) => e.session_id === selectedSession);
    if (incoming.length === 0) return;
    setSessionDetails((prev) => {
      if (!prev) return prev;
      const events = mergeEvents(prev.events || [], incoming);
      if (events === prev.events) return prev;
      return { ...prev, events };
    });
  }, [liveEvents, selectedSession]);

  const handleDownloadReport = async () => {
    if (!selectedSession) return;
    setReportGenerating(true);
    try {
      const response = await api.get(`/incidents/${selectedSession}/report`, {
        responseType: 'blob',
      });
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `DeceptionNet_Report_${selectedSession}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setReportsVersion((v) => v + 1);
      showToast('success', 'Report saved.', 3000);
    } catch (err) {
      console.error('Failed to download report', err);
      showToast('error', 'Report failed. The AI service may be offline.', 5000);
    } finally {
      setReportGenerating(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('demo_mode');
    setAuthenticated(false);
    setUser(null);
    setSelectedSession(null);
    setSessionDetails(null);
    setCurrentTab('sessions');
  };

  if (!authChecked) {
    return (
      <div className="boot-screen">
        <p>Connecting to core-api</p>
      </div>
    );
  }

  if (!authenticated) {
    return <LoginScreen onLogin={(profile) => { setUser(profile); setAuthenticated(true); }} />;
  }

  return (
    <div className="shell">
      <Header
        onLogout={handleLogout}
        user={user}
        connected={connected}
        sessionCount={sessions.length}
        eventCount={liveEvents.length}
        sessions={sessions}
      />
      <TabNav currentTab={currentTab} onSelect={setCurrentTab} liveCount={liveEvents.length} />

      {toast && (
        <div className={`toast toast-${toast.type}`}>{toast.message}</div>
      )}

      {loadError && currentTab === 'sessions' && (
        <div className="banner-error">{loadError}</div>
      )}

      {currentTab === 'sessions' && (
        <div className="grid">
          <SessionList
            sessions={sessions}
            loading={loading}
            selectedSession={selectedSession}
            onSelect={setSelectedSession}
          />
          <div className="work-panel">
            {!sessionDetails ? (
              <div className="details-empty">
                <p>Pick a session from the list.</p>
                <p>New hits from Cowrie, Dionaea, and the decoys appear here as they land.</p>
              </div>
            ) : (
              <SessionDetail
                session={sessionDetails}
                onDownloadReport={handleDownloadReport}
                reportGenerating={reportGenerating}
              />
            )}
          </div>
        </div>
      )}

      {currentTab === 'analytics' && <AnalyticsTab sessions={sessions} />}
      {currentTab === 'reports' && <ReportsTab refreshKey={reportsVersion} />}
      {currentTab === 'live' && <LiveFeedTab liveEvents={liveEvents} connected={connected} />}
    </div>
  );
}

export default App;
