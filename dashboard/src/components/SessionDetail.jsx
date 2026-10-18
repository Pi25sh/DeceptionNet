import { useState, useEffect } from 'react';
import TechniqueTag from './TechniqueTag';
import MitreTimeline from './MitreTimeline';
import { formatDuration, formatHoneypot, severityClass, severityLabel } from '../utils';

export default function SessionDetail({ session, onDownloadReport, reportGenerating }) {
  const [view, setView] = useState('events');

  useEffect(() => { setView('events'); }, [session?.id]);

  if (!session) {
    return (
      <div className="details-empty">
        <p>Select a session</p>
        <p>Live events from Cowrie SSH, Dionaea, and custom decoys stream here in real time.</p>
      </div>
    );
  }

  const techniques = session.techniques_detail || [];
  const events = session.events || [];
  const sev = severityClass(session.severity_score);
  const label = severityLabel(session.severity_score);
  const score = (session.severity_score ?? 0).toFixed(1);

  return (
    <div className="details-panel">
      {/* Header */}
      <div className="details-header">
        <div className="details-identity">
          <div className="details-ip">{session.src_ip || 'unknown'}</div>
          <div className="details-submeta">
            <span className="honeypot-badge">{formatHoneypot(session.honeypot)}</span>
            <span className={`score-badge ${sev}`}>{label} {score}</span>
            <span className="muted">Duration: {formatDuration(session.start_time, session.end_time)}</span>
            <span className="mono muted" title={session.id} style={{ fontSize: '0.78rem', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {session.id}
            </span>
          </div>
        </div>
        <button
          id="btn-generate-report"
          type="button"
          className="btn"
          onClick={onDownloadReport}
          disabled={reportGenerating}
        >
          {reportGenerating ? (
            <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Writing PDF…</>
          ) : (
            '⬇ Generate Report'
          )}
        </button>
      </div>

      {/* AI Summary */}
      {session.ai_summary ? (
        <div className="threat-assessment-panel">
          <div className="threat-assessment-header">
            <span className="threat-assessment-title">AI Threat Assessment</span>
            <span className="threat-assessment-engine">ai-service · gemini</span>
          </div>
          <p className="threat-assessment-content">{session.ai_summary}</p>
        </div>
      ) : (
        <div className="threat-assessment-panel" style={{ borderLeftColor: 'var(--border-highlight)', background: 'transparent' }}>
          <p className="muted" style={{ fontSize: '0.9rem' }}>
            AI summary appears after command or download events are analysed by the AI service.
          </p>
        </div>
      )}

      {/* Subnav */}
      <div className="detail-subnav">
        <div className="subnav-tabs">
          <button
            type="button"
            className={`subnav-btn ${view === 'events' ? 'active' : ''}`}
            onClick={() => setView('events')}
          >
            Events <span style={{ fontSize: '0.8rem', marginLeft: 4, opacity: 0.7 }}>({events.length})</span>
          </button>
          <button
            type="button"
            className={`subnav-btn ${view === 'chain' ? 'active' : ''}`}
            onClick={() => setView('chain')}
          >
            Attack Chain <span style={{ fontSize: '0.8rem', marginLeft: 4, opacity: 0.7 }}>({techniques.length})</span>
          </button>
        </div>
        <div className="tags" style={{ gap: 6 }}>
          {techniques.slice(0, 5).map((t, i) => (
            <TechniqueTag key={i} technique={t} compact />
          ))}
        </div>
      </div>

      {/* Content */}
      {view === 'chain' ? (
        <MitreTimeline session={session} />
      ) : events.length === 0 ? (
        <div className="details-empty">
          <p>No events stored for this session yet.</p>
        </div>
      ) : (
        <div className="timeline">
          {events.map((e, i) => (
            <div key={`${e.timestamp}-${i}`} className="timeline-item">
              <div className="timeline-time">
                {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}
              </div>
              <div className="timeline-content">
                <div className="timeline-content-top">
                  <span className={`event-type-badge ${e.event_type}`}>{e.event_type}</span>
                  {e.honeypot && <span className="honeypot-badge">{formatHoneypot(e.honeypot)}</span>}
                  {e.mitre_technique && (
                    <span style={{ fontSize: '0.75rem', color: 'var(--warning)', fontFamily: 'var(--font-mono)' }}>
                      {e.mitre_technique}
                    </span>
                  )}
                </div>
                <div className="event-message">{e.message}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
