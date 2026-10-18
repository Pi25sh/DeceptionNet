import { useMemo, useState } from 'react';
import TechniqueTag from './TechniqueTag';
import { formatDuration, formatHoneypot, severityClass, severityLabel } from '../utils';

function SessionCard({ session, selected, onSelect }) {
  const techniques = session.techniques_detail || [];
  const sev = severityClass(session.severity_score);
  const label = severityLabel(session.severity_score);
  const score = (session.severity_score ?? 0).toFixed(1);

  return (
    <button
      type="button"
      id={`session-${session.id}`}
      className={`session-card ${selected ? 'active' : ''}`}
      onClick={() => onSelect(session.id)}
    >
      <div className="session-card-top">
        <span className="session-ip">{session.src_ip || 'unknown'}</span>
        <span className={`score-badge ${sev}`}>{label} {score}</span>
      </div>
      <div className="session-meta-row">
        <span className="honeypot-badge">{formatHoneypot(session.honeypot)}</span>
        <span>{formatDuration(session.start_time, session.end_time)}</span>
      </div>
      <div className="session-time-text">
        {session.start_time ? new Date(session.start_time).toLocaleString() : '—'}
      </div>
      <div className="tags">
        {techniques.slice(0, 3).map((t, i) => (
          <TechniqueTag key={i} technique={t} compact />
        ))}
        {techniques.length === 0 && (
          <span className="muted" style={{ fontSize: '0.78rem' }}>No techniques yet</span>
        )}
      </div>
    </button>
  );
}

export default function SessionList({ sessions, loading, selectedSession, onSelect }) {
  const [query, setQuery] = useState('');
  const [honeypot, setHoneypot] = useState('all');

  const pots = useMemo(() => {
    const set = new Set(sessions.map((s) => formatHoneypot(s.honeypot)));
    return ['all', ...[...set].sort()];
  }, [sessions]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sessions.filter((s) => {
      if (honeypot !== 'all' && formatHoneypot(s.honeypot) !== honeypot) return false;
      if (!q) return true;
      const hay = `${s.src_ip} ${s.id} ${s.honeypot} ${(s.techniques || []).join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [sessions, query, honeypot]);

  return (
    <div className="session-panel">
      <div className="panel-header">
        <h2>Sessions</h2>
        <span className="mono muted" style={{ fontSize: '0.85rem' }}>{filtered.length}</span>
      </div>

      <div className="session-toolbar">
        <input
          id="session-search"
          className="session-search-input"
          type="search"
          placeholder="Filter by IP, id, technique…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="session-filter-row">
          {pots.map((p) => (
            <button
              key={p}
              type="button"
              className={`filter-pill ${honeypot === p ? 'active' : ''}`}
              onClick={() => setHoneypot(p)}
            >
              {p === 'all' ? 'All' : p}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="session-list">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="session-card skeleton" style={{ height: 96 }} />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="details-empty">
          <p>No sessions yet</p>
          <p style={{ fontSize: '0.9rem' }}>
            Honeypot events from Cowrie, Dionaea and custom decoys appear here in real time.
          </p>
        </div>
      ) : (
        <div className="session-list">
          {filtered.map((s) => (
            <SessionCard
              key={s.id}
              session={s}
              selected={selectedSession === s.id}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  );
}
