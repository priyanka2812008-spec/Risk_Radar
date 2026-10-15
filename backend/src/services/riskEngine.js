/**
 * Predictive Risk Scoring Engine
 * Correlates signals from all intelligence sources into an explainable composite risk score.
 * 
 * Architecture:
 * Domain Intelligence:     20 points
 * Infrastructure:          20 points
 * Threat Intelligence:     20 points
 * Website Classification:  20 points
 * Identity & Trust:        10 points
 * Behavioral/Content:      10 points
 * Total:                  100 points
 * 
 * Risk Levels:
 * 0-20  → LOW
 * 21-40 → GUARDED
 * 41-60 → MEDIUM
 * 61-80 → HIGH
 * 81-100 → CRITICAL
 * 
 * IMPORTANT: Every score must have explainable contributing signals.
 * Do NOT hard-code fake scores.
 */

import { v4 as uuidv4 } from 'uuid';

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

/**
 * Score configuration - weights are configurable
 */
const DEFAULT_WEIGHTS = {
  domainIntelligence: { maxPoints: 20, label: 'Domain Intelligence' },
  infrastructure: { maxPoints: 20, label: 'Infrastructure Intelligence' },
  threatIntelligence: { maxPoints: 20, label: 'Threat Intelligence' },
  websiteClassification: { maxPoints: 20, label: 'Website Classification' },
  identityTrust: { maxPoints: 10, label: 'Identity & Trust Signals' },
  behavioralContent: { maxPoints: 10, label: 'Behavioral / Content Signals' }
};

/**
 * Risk level thresholds
 */
const RISK_LEVELS = [
  { max: 20, level: 'LOW', color: '#22c55e', description: 'Minimal risk indicators detected.' },
  { max: 40, level: 'GUARDED', color: '#3b82f6', description: 'Some risk signals present — standard monitoring recommended.' },
  { max: 60, level: 'MEDIUM', color: '#f59e0b', description: 'Multiple risk signals detected — elevated caution recommended.' },
  { max: 80, level: 'HIGH', color: '#ef4444', description: 'Significant risk indicators — avoid interaction until verified.' },
  { max: 100, level: 'CRITICAL', color: '#dc2626', description: 'Severe risk profile — immediate avoidance recommended.' }
];

function getRiskLevel(score) {
  for (const level of RISK_LEVELS) {
    if (score <= level.max) return level;
  }
  return RISK_LEVELS[RISK_LEVELS.length - 1];
}

/**
 * Determine UNKNOWN BUT SUSPICIOUS state
 */
function isUnknownButSuspicious(components) {
  const tiClean = components.threatIntelligence.score <= 2;
  const hasOtherRiskSignals = (
    components.domainIntelligence.score >= 10 ||
    components.infrastructure.score >= 8 ||
    components.websiteClassification.score >= 10 ||
    components.identityTrust.score >= 6
  );
  const totalExcludingTI = components.domainIntelligence.score +
    components.infrastructure.score +
    components.websiteClassification.score +
    components.identityTrust.score +
    components.behavioralContent.score;
  
  return tiClean && hasOtherRiskSignals && totalExcludingTI >= 30;
}

/**
 * Calculate behavioral/content risk score from content signals
 */
function calculateBehavioralScore(classification, domain) {
  const h = hashCode(domain);
  let score = 0;
  const signals = [];
  
  const contentSignals = classification?.contentSignals || [];
  
  // Count concerning content signal categories
  const roiPromises = contentSignals.filter(s => s.category === 'roi_promise').length;
  const referralSignals = contentSignals.filter(s => s.category === 'referral_program').length;
  const depositSignals = contentSignals.filter(s => s.category === 'deposit_language').length;
  const bonusSignals = contentSignals.filter(s => s.category === 'bonus_promise').length;
  const withdrawalTraps = contentSignals.filter(s => s.category === 'withdrawal_trap').length;
  const urgencySignals = contentSignals.filter(s => s.category === 'urgency').length;
  const credentialSignals = contentSignals.filter(s => s.category === 'credential_harvesting').length;
  
  if (roiPromises > 0) {
    score += Math.min(4, roiPromises * 2);
    signals.push({ signal: 'ROI/profit promises detected', impact: Math.min(4, roiPromises * 2), detail: `${roiPromises} unrealistic return promise(s) found in content.` });
  }
  if (referralSignals > 0) {
    score += Math.min(3, referralSignals * 2);
    signals.push({ signal: 'Referral/recruitment pattern', impact: Math.min(3, referralSignals * 2), detail: 'Multi-level referral or recruitment commission detected.' });
  }
  if (depositSignals > 0) {
    score += Math.min(2, depositSignals);
    signals.push({ signal: 'Deposit solicitation', impact: Math.min(2, depositSignals), detail: 'Active deposit solicitation with monetary amounts detected.' });
  }
  if (bonusSignals > 0) {
    score += Math.min(2, bonusSignals);
    signals.push({ signal: 'Bonus/incentive promises', impact: Math.min(2, bonusSignals), detail: 'Signup bonus or deposit matching promises detected.' });
  }
  if (withdrawalTraps > 0) {
    score += Math.min(4, withdrawalTraps * 3);
    signals.push({ signal: 'Withdrawal trap mechanics', impact: Math.min(4, withdrawalTraps * 3), detail: 'Fee or tax requirements for withdrawals detected — potential capital detention.' });
  }
  if (urgencySignals > 0) {
    score += Math.min(2, urgencySignals);
    signals.push({ signal: 'Urgency/pressure tactics', impact: Math.min(2, urgencySignals), detail: 'Artificial urgency or time pressure cues detected.' });
  }
  if (credentialSignals > 0) {
    score += Math.min(4, credentialSignals * 3);
    signals.push({ signal: 'Credential harvesting indicators', impact: Math.min(4, credentialSignals * 3), detail: 'Form-based credential collection detected.' });
  }
  
  return { score: Math.min(10, score), signals };
}

/**
 * Main risk scoring engine
 * Correlates all intelligence sources into a single explainable score
 */
export function calculateRiskScore(domainIntelligence, threatIntelligence, infrastructure, classification, identity, domain) {
  const h = hashCode(domain);
  
  // === Component scores (each capped at their max points) ===
  const behavioral = calculateBehavioralScore(classification, domain);
  
  const components = {
    domainIntelligence: {
      score: Math.min(20, domainIntelligence?.riskScore || 0),
      maxPoints: 20,
      label: 'Domain Intelligence',
      signals: domainIntelligence?.signals || []
    },
    infrastructure: {
      score: Math.min(20, infrastructure?.riskScore || 0),
      maxPoints: 20,
      label: 'Infrastructure Intelligence',
      signals: infrastructure?.signals || []
    },
    threatIntelligence: {
      score: Math.min(20, threatIntelligence?.riskScore || 0),
      maxPoints: 20,
      label: 'Threat Intelligence',
      signals: threatIntelligence?.providers?.filter(p => p.status === 'DETECTED').map(p => ({
        signal: `Detected by ${p.provider}`,
        impact: Math.round(20 / 5),
        detail: `${p.detections}/${p.totalEngines} detections — category: ${p.category}`
      })) || []
    },
    websiteClassification: {
      score: Math.min(20, classification?.riskScore || 0),
      maxPoints: 20,
      label: 'Website Classification',
      signals: [{
        signal: `Classified as: ${classification?.primary || 'Unknown'}`,
        impact: classification?.riskScore || 0,
        detail: `${classification?.confidence || 0}% confidence — ${classification?.explanation || 'N/A'}`
      }]
    },
    identityTrust: {
      score: Math.min(10, identity?.riskScore || 0),
      maxPoints: 10,
      label: 'Identity & Trust Signals',
      signals: identity?.checks?.filter(c => c.status === 'NEGATIVE').map(c => ({
        signal: c.signal,
        impact: c.severity === 'HIGH' ? 3 : c.severity === 'MEDIUM' ? 2 : 1,
        detail: c.detail
      })) || []
    },
    behavioralContent: {
      score: Math.min(10, behavioral.score),
      maxPoints: 10,
      label: 'Behavioral / Content Signals',
      signals: behavioral.signals
    }
  };
  
  // === Total score ===
  const totalScore = Math.min(100, Math.max(0,
    components.domainIntelligence.score +
    components.infrastructure.score +
    components.threatIntelligence.score +
    components.websiteClassification.score +
    components.identityTrust.score +
    components.behavioralContent.score
  ));
  
  const riskLevel = getRiskLevel(totalScore);
  
  // === Unknown But Suspicious state ===
  const unknownSuspicious = isUnknownButSuspicious(components);
  
  let statusLabel;
  if (unknownSuspicious) {
    statusLabel = 'UNKNOWN BUT SUSPICIOUS';
  } else if (totalScore <= 20) {
    statusLabel = 'LOW RISK';
  } else if (totalScore <= 40) {
    statusLabel = 'GUARDED';
  } else if (totalScore <= 60) {
    statusLabel = 'ELEVATED RISK';
  } else if (totalScore <= 80) {
    statusLabel = 'HIGH RISK';
  } else {
    statusLabel = 'CRITICAL RISK';
  }
  
  // === Top contributing factors (sorted by impact) ===
  const allSignals = Object.values(components).flatMap(c =>
    c.signals.map(s => ({ ...s, category: c.label }))
  ).sort((a, b) => (b.impact || 0) - (a.impact || 0));
  
  const topFactors = allSignals.filter(s => (s.impact || 0) > 0).slice(0, 8);
  const positiveFactors = allSignals.filter(s => (s.impact || 0) < 0).slice(0, 4);
  
  // === Risk description ===
  let description;
  if (unknownSuspicious) {
    description = 'No confirmed threat-intelligence listing was found. However, multiple independent risk signals indicate elevated risk. Additional investigation is recommended before interaction.';
  } else if (totalScore <= 20) {
    description = 'Low observed risk across all intelligence dimensions. Standard monitoring recommended.';
  } else if (totalScore <= 40) {
    description = 'Some risk signals detected but below critical thresholds. Elevated awareness advised.';
  } else if (totalScore <= 60) {
    description = 'Multiple risk indicators detected across analysis dimensions. Proceed with caution.';
  } else if (totalScore <= 80) {
    description = 'Significant risk indicators detected. Avoid interaction until independently verified.';
  } else {
    description = 'Critical risk profile detected. Immediate avoidance recommended.';
  }
  
  // === Generate scan ID and verification token ===
  const scanId = `scan_${uuidv4().replace(/-/g, '').substring(0, 12)}`;
  const verificationToken = `RR-${new Date().getFullYear()}-${uuidv4().substring(0, 4).toUpperCase()}`;
  
  return {
    scanId,
    totalScore,
    riskLevel: riskLevel.level,
    riskColor: riskLevel.color,
    riskDescription: riskLevel.description,
    statusLabel,
    unknownSuspicious,
    description,
    components,
    topFactors,
    positiveFactors,
    verificationToken,
    timestamp: new Date().toISOString()
  };
}
