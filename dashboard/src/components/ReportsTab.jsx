import { useEffect, useState, useCallback } from 'react';
import { api } from '../hooks/useWebSocket';
import { severityClass, severityLabel } from '../utils';

function formatBytes(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

export default function ReportsTab({ refreshKey }) {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/reports');
      setReports(res.data);
      setError('');
    } catch {
      setError('Could not load reports from core-api.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load, refreshKey]);

  const handleDownload = async (report) => {
    try {
      const response = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' });
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', report.filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      setError('Download failed.');
    }
  };

  return (
    <div style={{ padding: '32px', maxWidth: '1100px', margin: '0 auto' }}>
      <div className="panel-header" style={{ marginBottom: 24 }}>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.5rem', fontWeight: 600 }}>Incident Reports</h2>
        <button id="reports-reload" type="button" className="btn btn-ghost btn-small" onClick={load}>
          ↻ Reload
        </button>
      </div>

      {error && <div className="banner-error" style={{ marginBottom: 16 }}>{error}</div>}

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[1, 2, 3].map((i) => (
            <div key={i} className="skeleton" style={{ height: 56, borderRadius: 8 }} />
          ))}
        </div>
      ) : reports.length === 0 ? (
        <div className="details-empty" style={{ padding: '80px 0' }}>
          <p>No reports generated yet</p>
          <p style={{ fontSize: '0.9rem' }}>
            Open a session and click <strong>Generate Report</strong> — the PDF is written live through core-api.
          </p>
        </div>
      ) : (
        <div className="report-table-wrap">
          <table className="report-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Source IP</th>
                <th>Severity</th>
                <th>Generated</th>
                <th>By</th>
                <th>Size</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td className="report-session-id" title={r.session_id}>{r.session_id}</td>
                  <td className="mono" style={{ fontSize: '0.9rem' }}>{r.src_ip}</td>
                  <td>
                    <span className={`score-badge ${severityClass(r.severity_score)}`}>
                      {severityLabel(r.severity_score)} {r.severity_score}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.88rem', color: 'var(--text-muted)' }}>
                    {r.generated_at ? new Date(r.generated_at).toLocaleString() : '—'}
                  </td>
                  <td style={{ fontSize: '0.88rem' }}>{r.generated_by || '—'}</td>
                  <td className="mono" style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    {formatBytes(r.file_size)}
                  </td>
                  <td>
                    <button
                      id={`download-report-${r.id}`}
                      type="button"
                      className="btn btn-ghost btn-small"
                      onClick={() => handleDownload(r)}
                    >
                      ⬇ PDF
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
