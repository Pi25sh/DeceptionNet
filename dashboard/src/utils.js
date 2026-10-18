export function severityClass(score) {
  if (score >= 4) return 'score-critical';
  if (score >= 2.5) return 'score-high';
  if (score >= 1) return 'score-med';
  return 'score-low';
}

export function severityBucket(score) {
  if (score >= 2.5) return 'high';
  if (score >= 1) return 'med';
  return 'low';
}

export function severityLabel(score) {
  if (score >= 4) return 'Critical';
  if (score >= 2.5) return 'High';
  if (score >= 1) return 'Elevated';
  return 'Low';
}

export function formatHoneypot(name) {
  if (!name) return 'Unknown decoy';
  const lower = name.toLowerCase();
  if (lower.includes('cowrie')) return 'Cowrie SSH';
  if (lower.includes('dionaea')) return 'Dionaea';
  if (lower.includes('target')) return 'Attack target';
  if (lower.includes('decoy')) return 'Custom decoy';
  return name;
}

export function formatDuration(startTime, endTime) {
  if (!startTime) return '—';
  const start = new Date(startTime).getTime();
  const end = endTime ? new Date(endTime).getTime() : Date.now();
  const diffSec = Math.max(1, Math.round((end - start) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ${diffSec % 60}s`;
  return `${(diffSec / 3600).toFixed(1)}h`;
}
