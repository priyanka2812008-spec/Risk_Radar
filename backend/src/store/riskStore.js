import crypto from 'crypto';
import { Scan } from '../models/Scan.js';
import { Watchlist } from '../models/Watchlist.js';
import { Report } from '../models/Report.js';
import { ApiKey } from '../models/ApiKey.js';
import { getDBStatus } from '../config/db.js';
import { runFullAssessment } from '../services/assessment.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Risk Radar store.
 * Memory is the working set (newest first). When MongoDB is connected it is hydrated
 * from the database on boot and every write goes through to the database, so the
 * API, the stats and the database never disagree.
 */

const MAX_SCANS = 500;

let scans = [];
let reports = [];
let watchlist = [];
let apiKeys = [];
let queue = [];

const SEED_TARGETS = [
  'https://github.com',
  'https://alpha-defi-stake.io/pools',
  'https://phish-login-portal.cfd/auth',
  'https://secure-fintech-bank.com',
  'https://scam-crypto-yield.xyz/invest'
];

const QUEUE_STATUSES = ['New', 'Investigating', 'Reviewed', 'Blocked', 'Allowed'];

const persist = async (label, fn) => {
  if (!getDBStatus()) return;
  try {
    await fn();
  } catch (err) {
    console.warn(`[RISK RADAR DB] ${label}: ${err.message}`);
  }
};

const stripMongo = ({ _id, __v, ...rest }) => rest;

const publicKey = ({ rawToken, keyHash, ...rest }) => rest;

/**
 * Lightweight scan shape for lists — full records are fetched by id.
 */
export const summarizeScan = (s) => ({
  id: s.id,
  url: s.url,
  domain: s.domain,
  timestamp: s.timestamp,
  score: s.score,
  risk_level: s.risk_level,
  primaryPattern: s.primaryPattern,
  verdict: s.verdict,
  classification: s.classification ? { primary: s.classification.primary, confidence: s.classification.confidence } : null,
  recommendedAction: s.recommendedAction ? { action: s.recommendedAction.action } : null,
  unknownSuspicious: Boolean(s.preExecution?.scoring?.unknownSuspicious || s.passport?.unknownSuspicious),
  engineScores: s.engineScores || null
});

const buildReport = (assessment) => ({
  id: `rep_${assessment.id.replace('scan_', '')}`,
  scan_id: assessment.id,
  title: `Digital Risk Passport: ${assessment.domain}`,
  reportType: 'Business Risk Passport',
  summary: `Evaluation of ${assessment.domain}. Composite risk score ${assessment.score}/100 (${assessment.risk_level}). Primary pattern: "${assessment.primaryPattern}".`,
  recommendations: assessment.recommendedAction?.immediateSteps || [],
  riskScore: assessment.score,
  riskLevel: assessment.risk_level,
  targetUrl: assessment.url,
  analysisVersion: 'RR-SEC-v4.2.1',
  generated_at: new Date(),
  passportDetails: {
    website: assessment.domain,
    overallRisk: assessment.score,
    riskLevel: assessment.risk_level,
    riskDNA: assessment.riskDNA,
    topRiskPatterns: assessment.detectedPatterns,
    evidenceSummary: (assessment.topReasons || []).map(r => r.reason),
    recommendedAction: assessment.recommendedAction?.action,
    complianceStatus: assessment.score > 50 ? 'NON-COMPLIANT / FLAGGED' : 'STANDARD OPERATING CLEARANCE'
  }
});

/**
 * Add (or refresh) a SOC incident for a high-risk scan. One open incident per domain.
 */
const upsertIncident = (assessment) => {
  if (assessment.score < 50) return;
  const existing = queue.find(q => q.domain === assessment.domain);
  if (existing) {
    Object.assign(existing, {
      url: assessment.url,
      risk: assessment.risk_level,
      score: assessment.score,
      detectedPattern: assessment.primaryPattern,
      scanId: assessment.id,
      lastUpdated: new Date()
    });
    if (existing.status === 'Reviewed' || existing.status === 'Allowed') existing.status = 'New';
    return;
  }
  queue.unshift({
    id: `inc_${uuidv4().replace(/-/g, '').substring(0, 6)}`,
    url: assessment.url,
    domain: assessment.domain,
    risk: assessment.risk_level,
    score: assessment.score,
    assignedTo: 'Unassigned',
    status: 'New',
    detectedPattern: assessment.primaryPattern,
    scanId: assessment.id,
    lastUpdated: new Date()
  });
};

const toHistory = (timeline = []) =>
  timeline.map(t => ({ date: new Date(t.date), score: t.score, note: t.majorChanges }));

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

const hydrateFromDB = async () => {
  if (!getDBStatus()) return;
  try {
    const [dbScans, dbReports, dbWatch, dbKeys] = await Promise.all([
      Scan.find().sort({ timestamp: -1 }).limit(MAX_SCANS).lean(),
      Report.find().sort({ generated_at: -1 }).limit(MAX_SCANS).lean(),
      Watchlist.find().sort({ createdAt: -1 }).lean(),
      ApiKey.find().sort({ createdAt: -1 }).lean()
    ]);
    scans = dbScans.map(stripMongo);
    reports = dbReports.map(stripMongo);
    watchlist = dbWatch.map(stripMongo);
    apiKeys = dbKeys.map(stripMongo);
    console.log(`[RISK RADAR DB] Loaded ${scans.length} scans, ${watchlist.length} watchlist items, ${apiKeys.length} API keys.`);
  } catch (err) {
    console.warn('[RISK RADAR DB] Hydration failed, continuing in memory:', err.message);
  }
};

export const initSeedData = async () => {
  await hydrateFromDB();

  if (scans.length === 0) {
    console.log('[RISK RADAR] Generating benchmark scans...');
    for (const url of SEED_TARGETS) {
      const assessment = await runFullAssessment(url);
      await saveScanAssessment(assessment);
      if (assessment.score > 40) {
        await addToWatchlist({
          url: assessment.url,
          domain: assessment.domain,
          current_score: assessment.score,
          risk_level: assessment.risk_level,
          alert_notes: `${assessment.primaryPattern} — continuous monitoring`,
          history: toHistory(assessment.timeline)
        });
      }
    }
  }

  if (apiKeys.length === 0) {
    const seededKeys = [
      { name: 'SOC automated triage pipeline', monthlyUsed: 14820, rateLimitPerMin: 120, ageDays: 30 },
      { name: 'CI/CD supply chain scanner', monthlyUsed: 3120, rateLimitPerMin: 60, ageDays: 14 }
    ];
    for (const k of seededKeys) {
      const key = await createApiKey(k.name);
      Object.assign(key, {
        monthlyUsed: k.monthlyUsed,
        rateLimitPerMin: k.rateLimitPerMin,
        createdAt: new Date(Date.now() - k.ageDays * 86400000),
        lastUsed: new Date(Date.now() - 1000 * 60 * 12)
      });
      await persist('seed key', () => ApiKey.updateOne({ id: key.id }, { $set: publicKey(key) }));
    }
  }

  // Rebuild the SOC queue from the latest high-risk scan per domain
  queue = [];
  const seen = new Set();
  for (const s of scans) {
    if (seen.has(s.domain) || s.score < 50) continue;
    seen.add(s.domain);
    queue.push({
      id: `inc_${s.id.replace('scan_', '').substring(0, 6)}`,
      url: s.url,
      domain: s.domain,
      risk: s.risk_level,
      score: s.score,
      assignedTo: 'Unassigned',
      status: 'New',
      detectedPattern: s.primaryPattern,
      scanId: s.id,
      lastUpdated: new Date(s.timestamp)
    });
    if (queue.length >= 12) break;
  }
  if (queue[0]) Object.assign(queue[0], { status: 'Investigating', assignedTo: 'Sarah K. (Lead SOC)' });
  if (queue[1]) Object.assign(queue[1], { status: 'Blocked', assignedTo: 'Marcus Vance (Tier-2)' });

  console.log(`[RISK RADAR] Ready: ${scans.length} scans, ${watchlist.length} watchlist items, ${queue.length} open incidents.`);
};

// ---------------------------------------------------------------------------
// Scans & reports
// ---------------------------------------------------------------------------

export const getScans = async () => scans.map(summarizeScan);

export const findScan = (predicate) => scans.find(predicate) || null;

export const getScanById = async (id) => {
  const local = scans.find(s => s.id === id);
  if (local) return local;
  if (getDBStatus()) {
    try {
      const doc = await Scan.findOne({ id }).lean();
      if (doc) return stripMongo(doc);
    } catch {
      return null;
    }
  }
  return null;
};

export const saveScanAssessment = async (assessment) => {
  scans.unshift(assessment);
  if (scans.length > MAX_SCANS) scans.length = MAX_SCANS;

  const report = buildReport(assessment);
  reports.unshift(report);
  if (reports.length > MAX_SCANS) reports.length = MAX_SCANS;

  upsertIncident(assessment);

  await persist('save scan', async () => {
    await Scan.create(assessment);
    await Report.create(report);
  });

  return assessment;
};

export const getReports = async () => reports;

export const getReportById = async (id) =>
  reports.find(r => r.id === id || r.scan_id === id) || null;

// ---------------------------------------------------------------------------
// Watchlist
// ---------------------------------------------------------------------------

export const getWatchlist = async () => watchlist;

export const addToWatchlist = async (data) => {
  const domain = data.domain || new URL(data.url).hostname;
  const existing = watchlist.find(w => w.domain === domain);
  if (existing) {
    return { ...existing, alreadyTracked: true };
  }

  const item = {
    id: `wtch_${uuidv4().substring(0, 8)}`,
    user_id: data.user_id || 'usr_soc_analyst_01',
    organization_id: data.organization_id || 'org_acme_sec_default',
    url: data.url,
    domain,
    current_score: data.current_score ?? 50,
    previous_score: data.previous_score ?? null,
    risk_level: data.risk_level || 'MEDIUM',
    score_change: data.score_change || 0,
    monitoring_state: data.monitoring_state || 'Active Monitoring',
    frequency: ['Hourly', 'Daily', 'Weekly'].includes(data.frequency) ? data.frequency : 'Daily',
    last_scan: new Date(),
    alert_notes: data.alert_notes || 'Continuous monitoring',
    history: data.history || [],
    createdAt: new Date()
  };

  watchlist.unshift(item);
  await persist('add watchlist item', () => Watchlist.create(item));
  return item;
};

export const updateWatchlistAfterScan = async (id, assessment) => {
  const item = watchlist.find(w => w.id === id);
  if (!item) return null;

  item.previous_score = item.current_score;
  item.current_score = assessment.score;
  item.score_change = item.current_score - item.previous_score;
  item.risk_level = assessment.risk_level;
  item.last_scan = new Date();
  item.monitoring_state = item.score_change >= 10 ? 'Alerting' : 'Active Monitoring';
  item.history = [...(item.history || []), { date: new Date(), score: assessment.score, note: 'Manual re-scan' }].slice(-30);

  await persist('update watchlist item', () =>
    Watchlist.updateOne({ id }, { $set: stripMongo(item) })
  );
  return item;
};

export const removeFromWatchlist = async (id) => {
  watchlist = watchlist.filter(w => w.id !== id);
  await persist('remove watchlist item', () => Watchlist.deleteOne({ id }));
  return { success: true };
};

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

export const getApiKeys = async () => apiKeys.map(publicKey);

export const createApiKey = async (name) => {
  const prefix = `rr_live_${crypto.randomBytes(2).toString('hex')}`;
  const rawToken = `${prefix}_${crypto.randomBytes(16).toString('hex')}`;
  const key = {
    id: `key_${uuidv4().substring(0, 8)}`,
    organization_id: 'org_acme_sec_default',
    name: (name || 'API token').toString().slice(0, 80),
    keyPrefix: prefix,
    keyHash: crypto.createHash('sha256').update(rawToken).digest('hex'),
    rateLimitPerMin: 60,
    monthlyLimit: 100000,
    monthlyUsed: 0,
    status: 'Active',
    lastUsed: null,
    createdAt: new Date()
  };

  apiKeys.unshift(key);
  await persist('create api key', () => ApiKey.create(key));
  // The raw token is returned exactly once and never stored
  return { ...publicKey(key), rawToken };
};

// ---------------------------------------------------------------------------
// SOC queue & stats
// ---------------------------------------------------------------------------

export const getInvestigationQueue = () => queue;

export const updateQueueItem = (id, updates) => {
  const item = queue.find(q => q.id === id);
  if (!item) return null;
  if (updates.status && QUEUE_STATUSES.includes(updates.status)) item.status = updates.status;
  if (typeof updates.assignedTo === 'string' && updates.assignedTo.trim()) item.assignedTo = updates.assignedTo.trim();
  item.lastUpdated = new Date();
  return item;
};

const dayKey = (d) => new Date(d).toISOString().slice(0, 10);

export const getGlobalStats = async () => {
  const total = scans.length;
  const count = (level) => scans.filter(s => s.risk_level === level).length;

  const patternDistribution = {};
  const classificationDistribution = {};
  for (const s of scans) {
    if (s.primaryPattern) patternDistribution[s.primaryPattern] = (patternDistribution[s.primaryPattern] || 0) + 1;
    const cls = s.classification?.primary;
    if (cls) classificationDistribution[cls] = (classificationDistribution[cls] || 0) + 1;
  }

  // Daily trend for the last 14 days
  const trend = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setUTCHours(0, 0, 0, 0);
    d.setUTCDate(d.getUTCDate() - i);
    const key = dayKey(d);
    const dayScans = scans.filter(s => dayKey(s.timestamp) === key);
    trend.push({
      date: key,
      scans: dayScans.length,
      highRisk: dayScans.filter(s => s.score >= 50).length,
      avgScore: dayScans.length ? Math.round(dayScans.reduce((a, s) => a + s.score, 0) / dayScans.length) : null
    });
  }

  // Latest result per domain
  const latestByDomain = [];
  const seen = new Set();
  for (const s of scans) {
    if (seen.has(s.domain)) continue;
    seen.add(s.domain);
    latestByDomain.push(s);
  }

  const today = dayKey(new Date());

  return {
    totalScans: total,
    uniqueDomains: latestByDomain.length,
    scansToday: scans.filter(s => dayKey(s.timestamp) === today).length,
    criticalCount: count('CRITICAL'),
    highCount: count('HIGH'),
    mediumCount: count('MEDIUM'),
    lowCount: count('LOW'),
    unknownSuspiciousCount: latestByDomain.filter(s => s.preExecution?.scoring?.unknownSuspicious).length,
    averageScore: total ? Math.round(scans.reduce((acc, s) => acc + s.score, 0) / total) : 0,
    watchlistCount: watchlist.length,
    activeIncidents: queue.filter(i => !['Reviewed', 'Allowed'].includes(i.status)).length,
    blockedCount: queue.filter(i => i.status === 'Blocked').length,
    patternDistribution,
    classificationDistribution,
    trend,
    topThreats: latestByDomain.filter(s => s.score >= 50).sort((a, b) => b.score - a.score).slice(0, 6).map(summarizeScan),
    recentScans: latestByDomain.slice(0, 10).map(summarizeScan)
  };
};
