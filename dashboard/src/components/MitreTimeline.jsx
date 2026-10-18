export default function MitreTimeline({ session }) {
  const techniques = session.techniques_detail || [];
  const events = session.events || [];

  if (techniques.length === 0) {
    return (
      <div className="details-empty">
        <p>No MITRE techniques recorded yet</p>
        <p style={{ fontSize: '0.9rem' }}>Techniques appear after events are analysed by the rule engine and AI service.</p>
      </div>
    );
  }

  return (
    <div className="mitre-timeline">
      {techniques.map((t, i) => {
        const isSemantic = t.source === 'semantic';
        const id = t.technique.split(' - ')[0];
        const name = t.technique.split(' - ').slice(1).join(' - ');
        const weight = t.weight ?? 0;
        const weightPct = Math.min((weight / 5) * 100, 100);
        const linked = events.filter((e) => e.mitre_technique?.startsWith(id));

        return (
          <div key={`${id}-${i}`} className={`mitre-node ${isSemantic ? 'semantic' : 'rule'}`}>
            <div className="mitre-node-line">
              <div className="mitre-node-dot">{String(i + 1).padStart(2, '0')}</div>
              {i < techniques.length - 1 && <div className="mitre-node-connector" />}
            </div>
            <div className="mitre-node-card">
              <div className="mitre-node-header">
                <span className="mitre-node-id">{id}</span>
                <span className={`technique-source ${t.source}`}>
                  {isSemantic ? '◈ Semantic AI' : '◆ Rule-based'}
                </span>
              </div>
              <div className="mitre-node-name">{name || 'Unnamed technique'}</div>
              <div className="mitre-weight-bar">
                <div
                  className={`mitre-weight-fill ${isSemantic ? 'semantic' : 'rule'}`}
                  style={{ width: `${weightPct}%` }}
                />
              </div>
              <div className="mitre-weight-label">confidence weight: {weight}</div>
              {linked.length > 0 && (
                <div className="mitre-node-events">
                  {linked.slice(0, 3).map((e, j) => (
                    <div key={j} className="mitre-node-event">
                      <span className="mitre-node-event-time">
                        {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}
                      </span>
                      <span className="mitre-node-event-msg">{e.message}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
