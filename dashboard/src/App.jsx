import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import { ShieldAlert, Terminal, Activity, Download, Clock } from 'lucide-react';

const API_BASE = 'http://localhost:8000';
// The /ws/live-events channel pushes a full session snapshot on connect, then
// per-event (and AI-summary) updates — replacing the old 3s polling.
const WS_URL = `${API_BASE.replace(/^http/, 'ws')}/ws/live-events`;

function App() {
  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetails, setSessionDetails] = useState(null);
  const [loading, setLoading] = useState(true);

  // Refs so the (stable) WS message handler always sees the current selection
  // without re-registering the socket on every state change.
  const selectedRef = useRef(null);
  useEffect(() => { selectedRef.current = selectedSession; }, [selectedSession]);

  // Replace-or-prepend a session in the list, preserving server order (newest first).
  const applySessionToSessionsList = useCallback((session) => {
    setSessions(prev => {
      const idx = prev.findIndex(s => s.id === session.id);
      if (idx === -1) return [session, ...prev];
      const next = [...prev];
      next[idx] = session;
      return next;
    });
  }, []);

  // One-shot history fetch when a session is selected; live updates then come
  // over the WebSocket.
  const fetchSessionDetails = useCallback(async (id) => {
    try {
      const res = await axios.get(`${API_BASE}/sessions/${id}`);
      setSessionDetails(res.data);
    } catch (err) {
      console.error("Failed to fetch session details", err);
    }
  }, []);

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'sessions') {
      // Fresh snapshot on (re)connect — resync selection against the server.
      setSessions(msg.data);
      setLoading(false);
      if (selectedRef.current) fetchSessionDetails(selectedRef.current);
    } else if (msg.type === 'session') {
      // AI summary / score refresh for one session.
      applySessionToSessionsList(msg.session);
      if (selectedRef.current === msg.session.id) {
        setSessionDetails(prev =>
          prev ? { ...prev, ...msg.session, events: prev.events } : prev
        );
      }
    } else if (msg.type === 'event') {
      const { session, event } = msg;
      applySessionToSessionsList(session);
      if (selectedRef.current === session.id) {
        setSessionDetails(prev => {
          if (!prev) return prev;
          // Dedupe against the events already pulled from /sessions/{id}.
          const exists = prev.events.some(e =>
            e.timestamp === event.timestamp &&
            e.event_type === event.event_type &&
            e.message === event.message
          );
          if (exists) return { ...prev, ...session, events: prev.events };
          return { ...prev, ...session, events: [...prev.events, event] };
        });
      }
    }
  }, [applySessionToSessionsList, fetchSessionDetails]);

  // Live channel: connect, then reconnect with backoff if core-api restarts.
  useEffect(() => {
    let ws;
    let closed = false;
    let retryMs = 1000;

    const connect = () => {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => { retryMs = 1000; };

      ws.onmessage = (event) => {
        try { handleWsMessage(JSON.parse(event.data)); } catch { /* ignore malformed */ }
      };

      ws.onclose = () => {
        if (closed) return;
        setTimeout(connect, retryMs);
        retryMs = Math.min(retryMs * 2, 30000); // 1s -> 2s -> ... -> 30s cap
      };

      ws.onerror = () => ws.close();
    };

    connect();
    return () => { closed = true; if (ws) ws.close(); };
  }, [handleWsMessage]);

  // Selection loads history once; the WS keeps it live afterwards.
  useEffect(() => {
    if (!selectedSession) { setSessionDetails(null); return; }
    fetchSessionDetails(selectedSession);
  }, [selectedSession, fetchSessionDetails]);

  const handleDownloadReport = async () => {
    if (!selectedSession) return;
    try {
      // Create a blob from the PDF stream
      const response = await axios.get(`${API_BASE}/incidents/${selectedSession}/report`, {
        responseType: 'blob',
      });
      // Create a link to download it
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `DeceptionNet_Report_${selectedSession}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error("Failed to download report", err);
      alert("Failed to generate report. Ensure AI service is running and API key is set.");
    }
  };

  const getScoreClass = (score) => {
    if (score >= 5) return 'score-high';
    if (score >= 2) return 'score-med';
    return 'score-low';
  };

  return (
    <div className="dashboard-container">
      <header className="header animate-fade-in">
        <h1>
          <ShieldAlert size={40} color="#3b82f6" />
          DeceptionNet
        </h1>
      </header>

      <div className="grid">
        {/* Left Column: Sessions List */}
        <div className="glass-panel animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <h2 style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={20} color="#94a3b8" />
            Live Sessions
          </h2>
          
          {loading ? (
            <div className="session-list">
              {[1,2,3].map(i => (
                <div key={i} className="session-card skeleton" style={{height: '100px'}}></div>
              ))}
            </div>
          ) : sessions.length === 0 ? (
            <div className="details-empty">
              <Terminal size={48} opacity={0.2} style={{marginBottom: '16px'}} />
              <p>No active sessions found.</p>
              <p style={{fontSize: '0.85rem', marginTop: '8px'}}>Waiting for attacker interaction...</p>
            </div>
          ) : (
            <div className="session-list">
              {sessions.map(s => (
                <div 
                  key={s.id} 
                  className={`session-card ${selectedSession === s.id ? 'active' : ''}`}
                  onClick={() => setSelectedSession(s.id)}
                >
                  <div className="session-header">
                    <span className="session-ip">{s.src_ip}</span>
                    <span className={`score-badge ${getScoreClass(s.severity_score)}`}>
                      Score: {s.severity_score}
                    </span>
                  </div>
                  <div className="session-time" style={{display: 'flex', alignItems: 'center', gap: '4px'}}>
                    <Clock size={12} />
                    {new Date(s.start_time).toLocaleString()}
                  </div>
                  <div className="tags">
                    {s.techniques.map((t, i) => (
                      <span key={i} className="tag">{t.split(' - ')[0]}</span>
                    ))}
                    {s.techniques.length === 0 && (
                      <span className="tag" style={{background: 'rgba(255,255,255,0.05)', color: '#94a3b8', borderColor: 'transparent'}}>
                        Recon Phase
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Session Details */}
        <div className="glass-panel animate-fade-in" style={{ animationDelay: '0.2s', minHeight: '600px' }}>
          {!selectedSession ? (
            <div className="details-empty">
              <p>Select a session to view details</p>
            </div>
          ) : !sessionDetails ? (
            <div className="details-empty">
              <div className="skeleton" style={{width: '100%', height: '200px'}}></div>
            </div>
          ) : (
            <div>
              <div className="details-header">
                <div>
                  <h2 style={{fontFamily: 'monospace', color: '#fff'}}>{sessionDetails.src_ip}</h2>
                  <p className="session-time">ID: {sessionDetails.id}</p>
                </div>
                <button className="btn" onClick={handleDownloadReport}>
                  <Download size={16} />
                  Generate Report
                </button>
              </div>

              {sessionDetails.ai_summary && (
                <div className="ai-summary-box">
                  <p>{sessionDetails.ai_summary}</p>
                </div>
              )}

              <h3 style={{marginBottom: '16px', color: '#94a3b8'}}>Event Timeline</h3>
              <div className="timeline">
                {sessionDetails.events.map((e, i) => (
                  <div key={i} className="timeline-item">
                    <div className="timeline-time">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </div>
                    <div className={`timeline-content ${e.mitre_technique ? 'has-mitre' : ''}`}>
                      <div className="event-type">{e.event_type}</div>
                      <div className="event-message">{e.message}</div>
                      {e.mitre_technique && (
                        <div style={{marginTop: '8px', fontSize: '0.75rem', color: '#fca5a5', fontWeight: 'bold'}}>
                          TAG: {e.mitre_technique}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
