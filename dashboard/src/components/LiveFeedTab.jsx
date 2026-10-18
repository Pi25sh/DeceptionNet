import { useMemo, useRef, useEffect, useState, useCallback } from 'react';
import { formatHoneypot } from '../utils';

const BUFFER = 10;
const ITEM_HEIGHT = 48;

export default function LiveFeedTab({ liveEvents, connected }) {
  const [paused, setPaused] = useState(false);
  const [typeFilter, setTypeFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const listRef = useRef(null);
  const frozenRef = useRef([]);
  const liveEventsRef = useRef(liveEvents);
  const [scrollInfo, setScrollInfo] = useState({ top: 0, height: 0 });

  liveEventsRef.current = liveEvents;

  const visible = paused ? frozenRef.current : liveEvents;
  const filtered = useMemo(() => {
    const t = typeFilter === 'all' ? null : typeFilter;
    const q = query.trim().toLowerCase();
    return visible.filter((e) => {
      if (t && e.event_type !== t) return false;
      if (q && !`${e.message} ${e.event_type} ${e.honeypot ?? ''} ${e.src_ip ?? ''}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [visible, typeFilter, query]);

  const totalCount = filtered.length;
  const startIndex = Math.max(0, Math.floor(scrollInfo.top / ITEM_HEIGHT) - BUFFER);
  const endIndex = Math.min(totalCount, Math.ceil((scrollInfo.top + scrollInfo.height) / ITEM_HEIGHT) + BUFFER);
  const visibleItems = filtered.slice(startIndex, endIndex);
  const topSpacer = startIndex * ITEM_HEIGHT;
  const bottomSpacer = (totalCount - endIndex) * ITEM_HEIGHT;

  const handleScroll = useCallback(() => {
    if (listRef.current) {
      setScrollInfo({ top: listRef.current.scrollTop, height: listRef.current.clientHeight });
    }
  }, []);

  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    el.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => el.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);

  useEffect(() => {
    if (autoScroll && !paused && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [filtered.length, autoScroll, paused]);

  const eventTypes = useMemo(() => {
    const types = new Set(liveEvents.map((e) => e.event_type).filter(Boolean));
    return ['all', ...types];
  }, [liveEvents]);

  const sessionCount = useMemo(() => {
    return new Set(liveEvents.map((e) => e.session_id).filter(Boolean)).size;
  }, [liveEvents]);

  const togglePause = useCallback(() => {
    setPaused((p) => {
      if (!p) frozenRef.current = liveEventsRef.current;
      return !p;
    });
  }, []);

  return (
    <div className="live-feed-panel">
      <div className="live-feed-toolbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600 }}>Live Event Stream</h2>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', color: paused ? 'var(--warning)' : connected ? 'var(--success)' : 'var(--danger)' }}>
            <span className={`link-dot ${connected && !paused ? 'on' : 'off'}`} style={{ background: paused ? 'var(--warning)' : undefined }} />
            {paused ? 'Paused' : connected ? 'Live' : 'Reconnecting'}
          </span>
        </div>
        <div className="live-feed-controls" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            id="live-search"
            className="live-search"
            type="search"
            placeholder="Search events…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ minWidth: 180, background: 'var(--bg-raised)', border: '1px solid var(--border-color)', color: 'var(--text-main)', padding: '8px 12px', borderRadius: 6, fontSize: '0.875rem' }}
          />
          <select
            id="live-type-filter"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-color)', color: 'var(--text-main)', padding: '8px 12px', borderRadius: 6, fontSize: '0.875rem' }}
          >
            {eventTypes.map((t) => (
              <option key={t} value={t}>{t === 'all' ? 'All types' : t}</option>
            ))}
          </select>
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '0.875rem', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
            Auto-scroll
          </label>
          <button
            id="live-pause-btn"
            type="button"
            className={`btn btn-ghost btn-small`}
            onClick={togglePause}
            style={{ borderColor: paused ? 'var(--success)' : 'var(--danger)', color: paused ? 'var(--success)' : 'var(--danger)' }}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
        </div>
      </div>

      {/* Status bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.82rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
        <span>{filtered.length} shown · {liveEvents.length} buffered</span>
        <span>{sessionCount} active sessions</span>
      </div>

      {/* Virtual list */}
      <div className="live-feed-list" ref={listRef}>
        {filtered.length === 0 ? (
          <div className="details-empty" style={{ padding: '60px 0' }}>
            <p>{paused ? 'Stream paused.' : 'Waiting for events from honeypot forwarders…'}</p>
          </div>
        ) : (
          <>
            {topSpacer > 0 && <div style={{ height: topSpacer, flexShrink: 0 }} />}
            {visibleItems.map((e, i) => (
              <div key={startIndex + i} className={`live-event ${e.event_type || ''}`}>
                <span className="live-event-time">
                  {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}
                </span>
                <span className="live-event-type">{e.event_type}</span>
                <span className="live-event-message">{e.message}</span>
                {e.honeypot && <span className="live-event-honeypot">{formatHoneypot(e.honeypot)}</span>}
                {e.mitre_technique && <span className="live-event-mitre">{e.mitre_technique}</span>}
              </div>
            ))}
            {bottomSpacer > 0 && <div style={{ height: bottomSpacer, flexShrink: 0 }} />}
          </>
        )}
      </div>
    </div>
  );
}
