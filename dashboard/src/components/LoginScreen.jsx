import { useState } from 'react';
import { api } from '../hooks/useWebSocket';

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);
      const response = await api.post('/api/v1/auth/login', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      localStorage.setItem('token', response.data.access_token);
      localStorage.removeItem('demo_mode');
      const me = await api.get('/api/v1/auth/me');
      onLogin(me.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Sign-in failed. Is core-api running on this host?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <aside className="login-aside">
        <div className="login-hero-brand">
          <img src="/logo-badge.png" alt="DeceptionNet Logo" className="login-hero-logo" />
          <p className="login-mark">DeceptionNet</p>
        </div>
        <h1>Real-time honeypot intelligence.</h1>
        <p>
          Monitor live attack sessions from Cowrie SSH, Dionaea, and custom decoys.
          AI-powered MITRE ATT&amp;CK attribution streams directly from your honeypot pipeline.
        </p>
        <div style={{ marginTop: 48, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {['Cowrie SSH Honeypot', 'Dionaea Malware Trap', 'Custom HTTP / Redis / SMTP Decoys', 'AI Threat Summaries · PDF Reports'].map((f) => (
            <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)', fontSize: '0.95rem' }}>
              <span style={{ color: 'var(--accent-primary)', fontSize: '1.1rem' }}>✓</span>
              {f}
            </div>
          ))}
        </div>
      </aside>

      <main className="login-main">
        <form id="login-form" onSubmit={handleSubmit} className="login-form">
          <div style={{ textAlign: 'center', marginBottom: 8 }}>
            <div className="login-card-logo-wrap">
              <img src="/logo-badge.png" alt="DeceptionNet" className="login-card-logo" />
            </div>
            <h2>Welcome back</h2>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginTop: 4 }}>Sign in to your operator account</p>
          </div>

          {error && (
            <div className="login-error" role="alert">{error}</div>
          )}

          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            autoFocus
            placeholder="admin"
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            placeholder="••••••••"
          />

          <button id="login-submit" type="submit" className="btn" disabled={loading}>
            {loading ? (
              <><span className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} /> Signing in…</>
            ) : (
              'Sign in →'
            )}
          </button>
        </form>
      </main>
    </div>
  );
}
