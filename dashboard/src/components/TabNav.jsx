const TABS = [
  { id: 'sessions', label: 'Sessions', icon: '⬡' },
  { id: 'analytics', label: 'Analytics', icon: '◈' },
  { id: 'reports', label: 'Reports', icon: '⬚' },
  { id: 'live', label: 'Live Feed', icon: '◉' },
];

export default function TabNav({ currentTab, onSelect, liveCount = 0 }) {
  return (
    <nav className="tab-nav" aria-label="Primary navigation">
      {TABS.map(({ id, label, icon }) => (
        <button
          key={id}
          type="button"
          id={`tab-${id}`}
          className={`tab-btn ${currentTab === id ? 'active' : ''}`}
          onClick={() => onSelect(id)}
        >
          <span className="tab-icon" aria-hidden="true">{icon}</span>
          {label}
          {id === 'live' && liveCount > 0 && (
            <span className="tab-count">{liveCount}</span>
          )}
        </button>
      ))}
    </nav>
  );
}
