import { useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, Cell,
} from 'recharts';
import { severityBucket } from '../utils';

const SEV_COLORS = { high: '#EF4444', med: '#F59E0B', low: '#10B981' };

const TOOLTIP_STYLE = {
  background: '#1A1E26',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '8px',
  fontSize: '13px',
  color: '#F3F4F6',
  boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
};

function StatTile({ label, value, accent }) {
  return (
    <div className="stat-tile">
      <div className="stat-value" style={accent ? { color: accent } : {}}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export default function AnalyticsTab({ sessions }) {
  const stats = useMemo(() => {
    const total = sessions.length;
    if (total === 0) {
      return { total: 0, avg: 0, highRisk: 0, techniqueCount: 0, severityData: [], timeData: [], topTechniques: [] };
    }

    const totalScore = sessions.reduce((s, x) => s + (x.severity_score || 0), 0);
    const highRisk = sessions.filter((s) => severityBucket(s.severity_score) === 'high').length;

    const buckets = { low: 0, med: 0, high: 0 };
    sessions.forEach((s) => { buckets[severityBucket(s.severity_score)]++; });
    const severityData = [
      { name: 'Low', value: buckets.low, color: SEV_COLORS.low },
      { name: 'Medium', value: buckets.med, color: SEV_COLORS.med },
      { name: 'High', value: buckets.high, color: SEV_COLORS.high },
    ];

    const byHour = new Map();
    sessions.forEach((s) => {
      if (!s.start_time) return;
      const d = new Date(s.start_time);
      const key = d.toISOString().slice(0, 13) + ':00';
      byHour.set(key, (byHour.get(key) || 0) + 1);
    });
    const keys = [...byHour.keys()].sort();
    const spansMultipleDays = keys.length >= 2
      && new Date(keys[0]).toDateString() !== new Date(keys[keys.length - 1]).toDateString();
    const timeData = keys.map((k) => ({
      time: spansMultipleDays
        ? new Date(k).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' })
        : new Date(k).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      sessions: byHour.get(k),
    }));

    const techCount = new Map();
    const techNames = new Map();
    sessions.forEach((s) => {
      (s.techniques_detail || []).forEach((t) => {
        const id = t.technique.split(' - ')[0];
        const name = t.technique.split(' - ').slice(1).join(' - ');
        techCount.set(id, (techCount.get(id) || 0) + 1);
        if (name && !techNames.has(id)) techNames.set(id, name);
      });
    });
    const topTechniques = [...techCount.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([id, count]) => ({ name: techNames.get(id) || id, count }));

    return { total, avg: totalScore / total, highRisk, techniqueCount: techCount.size, severityData, timeData, topTechniques };
  }, [sessions]);

  if (sessions.length === 0) {
    return (
      <div className="analytics-tab">
        <div className="details-empty" style={{ padding: '80px 0' }}>
          <p>No sessions to chart yet</p>
          <p style={{ fontSize: '0.9rem' }}>Charts populate automatically as honeypot data arrives.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="analytics-tab">
      <div className="stat-row">
        <StatTile label="Total Sessions" value={stats.total} />
        <StatTile label="Avg Severity" value={stats.avg.toFixed(1)} accent="var(--warning)" />
        <StatTile label="High Risk" value={stats.highRisk} accent="var(--danger)" />
        <StatTile label="MITRE Techniques" value={stats.techniqueCount} accent="var(--accent-primary)" />
      </div>

      <div className="chart-grid">
        <div className="chart-card">
          <h3 className="chart-title">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={stats.severityData} barCategoryGap="30%">
              <CartesianGrid strokeDasharray="3 6" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="name" stroke="#6B7280" fontSize={12} axisLine={false} tickLine={false} />
              <YAxis stroke="#6B7280" fontSize={12} allowDecimals={false} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Bar dataKey="value" name="Sessions" radius={[4, 4, 0, 0]}>
                {stats.severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3 className="chart-title">Sessions Over Time</h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={stats.timeData}>
              <defs>
                <linearGradient id="sessGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#66E2FF" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#66E2FF" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 6" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="time" stroke="#6B7280" fontSize={11} axisLine={false} tickLine={false} />
              <YAxis stroke="#6B7280" fontSize={12} allowDecimals={false} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area type="monotone" dataKey="sessions" stroke="#66E2FF" fill="url(#sessGrad)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card chart-card-wide">
          <h3 className="chart-title">Top MITRE ATT&CK Techniques</h3>
          {stats.topTechniques.length === 0 ? (
            <p className="muted">No techniques attributed yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={stats.topTechniques} layout="vertical" margin={{ left: 8 }}>
                <CartesianGrid strokeDasharray="3 6" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" stroke="#6B7280" fontSize={12} allowDecimals={false} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" stroke="#6B7280" fontSize={11} width={140} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Sessions" fill="#8B5CF6" radius={[0, 4, 4, 0]} fillOpacity={0.85} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
