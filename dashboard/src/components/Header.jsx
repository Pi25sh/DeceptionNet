import { useEffect, useMemo, useState } from 'react';
import { formatHoneypot } from '../utils';

export default function Header({ onLogout, user, connected, sessionCount, eventCount, sessions }) {
  const [clock, setClock] = useState(() => new Date());

  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const sensors = useMemo(() => {
    const names = new Set(
      (sessions || []).map((s) => formatHoneypot(s.honeypot)).filter(Boolean)
    );
    return names.size;
  }, [sessions]);

  const name = user?.username || 'operator';
  const initial = name.slice(0, 1).toUpperCase();

  return (
    <header className="topbar">
      <div className="brand-container">
        <img
          src="/logo-badge.png"
          alt="DeceptionNet Emblem"
          className="brand-logo"
        />
        <div className="brand-text-block">
          <span className="brand-name">DeceptionNet</span>
          <span className="brand-line">// honeypot intelligence console</span>
        </div>
      </div>

      <dl className="status-strip">
        <div>
          <dt>Status</dt>
          <dd className={connected ? 'ok' : 'warn'}>
            <span className={`link-dot ${connected ? 'on' : 'off'}`} />
            {connected ? 'Live' : 'Reconnecting'}
          </dd>
        </div>
        <div>
          <dt>Sessions</dt>
          <dd>{sessionCount}</dd>
        </div>
        <div>
          <dt>Events</dt>
          <dd>{eventCount}</dd>
        </div>
        <div>
          <dt>Sensors</dt>
          <dd>{sensors}</dd>
        </div>
        <div>
          <dt>UTC</dt>
          <dd>{clock.toUTCString().slice(17, 25)}</dd>
        </div>
      </dl>

      <div className="topbar-user">
        <div className="avatar" aria-hidden="true">{initial}</div>
        <span className="user-name">{name}</span>
        <button type="button" className="btn-text" onClick={onLogout}>
          Sign out
        </button>
      </div>
    </header>
  );
}
