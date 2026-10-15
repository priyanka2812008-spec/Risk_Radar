/* ------------------------------------------------------------------ */
/* Risk scale                                                          */
/* ------------------------------------------------------------------ */

export const RISK = {
  CRITICAL: { label: 'Critical', color: '#F43F5E', chip: 'border-risk-critical/40 bg-risk-critical/10 text-rose-200' },
  HIGH: { label: 'High', color: '#FB8A3C', chip: 'border-risk-high/40 bg-risk-high/10 text-orange-200' },
  MEDIUM: { label: 'Medium', color: '#FBBF24', chip: 'border-risk-medium/40 bg-risk-medium/10 text-amber-200' },
  GUARDED: { label: 'Guarded', color: '#60A5FA', chip: 'border-risk-guarded/40 bg-risk-guarded/10 text-sky-200' },
  LOW: { label: 'Low', color: '#2DD4A4', chip: 'border-risk-low/40 bg-risk-low/10 text-emerald-200' }
};

export const levelFromScore = (score) => {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
};

export const riskMeta = (level) => RISK[(level || '').toUpperCase()] || RISK.LOW;

export const scoreColor = (score) => riskMeta(levelFromScore(score)).color;

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */

export const timeAgo = (date) => {
  if (!date) return '—';
  const diff = Date.now() - new Date(date).getTime();
  const m = Math.round(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d} d ago`;
  return new Date(date).toLocaleDateString();
};

export const formatDateTime = (date) =>
  date
    ? new Date(date).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
    : '—';

export const hashString = (str = '') => {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h << 5) - h + str.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
};

/** Latest scan per domain, preserving newest-first order */
export const latestPerDomain = (scans = []) => {
  const seen = new Set();
  return scans.filter((s) => {
    if (!s?.domain || seen.has(s.domain)) return false;
    seen.add(s.domain);
    return true;
  });
};
