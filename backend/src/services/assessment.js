/**
 * Unified Assessment Service
 * Runs both intelligence engines for a target and reconciles them into one verdict.
 *
 * The legacy forensic engine (engine/scoringEngine.js) produces the detailed report
 * (Risk DNA, pillars, trust gap, signals). The pre-execution engine correlates domain,
 * threat-intel, infrastructure and identity signals and is better at catching new,
 * unlisted scam sites. Because "unknown != safe", the headline score is the higher of
 * the two, and every field derived from the headline score is rebuilt to match it.
 */

import { runComprehensiveRiskAssessment } from '../engine/scoringEngine.js';
import { runPreExecutionScan, normalizeTargetUrl } from './preExecutionScan.js';
import { collectLiveTelemetry } from './liveTelemetry.js';

const levelFor = (score) => {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
};

const VERDICTS = {
  CRITICAL: {
    verdict: 'CRITICAL RISK DETECTED',
    explanation: 'Severe risk indicators detected. Avoid interaction until the identified risks are independently verified.',
    action: 'BLOCK',
    rationale: 'Correlated intelligence indicates a high probability of fraud, credential theft or capital loss.',
    steps: [
      'Do not enter credentials, card details, UPI PINs or wallet seed phrases on this site.',
      'Add the domain and its nameservers to your DNS blocklist.',
      'Warn users who may have interacted with the site and reset any credentials they entered.',
      'Report the domain to the registrar and hosting provider abuse desks.'
    ]
  },
  HIGH: {
    verdict: 'HIGH RISK PROFILE',
    explanation: 'Multiple elevated risk indicators detected across domain, content, identity or infrastructure signals.',
    action: 'AVOID',
    rationale: 'Several independent signals point to elevated risk. Investigate before any interaction.',
    steps: [
      'Inspect the site only inside an isolated sandbox or virtual machine.',
      'Verify the operator’s legal entity and licensing with the relevant regulator.',
      'Avoid deposits or payments until the operator is independently verified.'
    ]
  },
  MEDIUM: {
    verdict: 'MODERATE RISK - REVIEW REQUIRED',
    explanation: 'Some risk indicators detected. Additional verification is recommended.',
    action: 'REVIEW',
    rationale: 'Contextual signals are present; verify before trusting the site with data or money.',
    steps: [
      'Add the domain to the watchlist to track score changes.',
      'Check WHOIS history, SSL renewal and DNS changes for inconsistencies.'
    ]
  }
};

/**
 * Fold pre-execution evidence into the forensic report: one domain age, Risk DNA that
 * reflects both engines, and the pre-execution signals listed in the evidence table.
 */
function mergeEvidence(assessment, pe) {
  const comps = pe.scoring?.components || {};
  const pct = (c) => (c && c.maxPoints ? Math.round((c.score / c.maxPoints) * 100) : 0);
  const ageDays = pe.intelligence?.domain?.ageDays;

  if (assessment.riskDNA) {
    const dna = assessment.riskDNA;
    const transparency = pe.intelligence?.identity?.transparencyScore;
    dna.domain = Math.max(dna.domain || 0, pct(comps.domainIntelligence));
    dna.reputation = Math.max(dna.reputation || 0, pct(comps.threatIntelligence), pct(comps.infrastructure));
    dna.content = Math.max(dna.content || 0, pct(comps.behavioralContent));
    dna.businessModel = Math.max(dna.businessModel || 0, pct(comps.websiteClassification));
    if (typeof transparency === 'number') dna.contactIdentity = Math.max(dna.contactIdentity || 0, 100 - transparency);
    // Scam sites rotate domains and content quickly
    if (!['Legitimate', 'Unknown'].includes(pe.classification?.primary)) dna.changeOverTime = Math.max(dna.changeOverTime || 0, 65);
  }

  if (typeof ageDays === 'number') {
    assessment.metadata = { ...assessment.metadata, domainAgeDays: ageDays };
    // Drop the forensic engine's own age estimate so the report shows a single age
    assessment.signals = (assessment.signals || []).filter(
      (sig) => !(sig.category === 'Domain' && /regist|age|tenure/i.test(sig.indicator || ''))
    );
  }

  const severityOf = (sev, impact) => sev || (impact >= 10 ? 'HIGH' : impact >= 5 ? 'MEDIUM' : 'LOW');
  const peSignals = [];
  for (const comp of Object.values(comps)) {
    for (const sig of comp.signals || []) {
      const impact = sig.scoreImpact ?? sig.impact ?? 0;
      peSignals.push({
        id: `pe_${peSignals.length}_${(sig.signal || '').slice(0, 12).replace(/W/g, '')}`,
        category: comp.label,
        indicator: sig.signal,
        evidence: sig.detail || sig.signal,
        severity: severityOf((sig.severity || '').toUpperCase() || null, impact),
        confidence: 85,
        scoreImpact: impact,
        signalType: impact >= 8 ? 'STRONG_INDICATOR' : impact > 0 ? 'CONTEXTUAL_SIGNAL' : 'BENIGN_SIGNAL',
        sourceType: 'Tier 2: Pre-execution correlation'
      });
    }
  }
  assessment.signals = [...peSignals, ...(assessment.signals || [])];
  assessment.signalsCount = {
    strong: assessment.signals.filter((x) => x.signalType === 'STRONG_INDICATOR').length,
    contextual: assessment.signals.filter((x) => x.signalType === 'CONTEXTUAL_SIGNAL').length,
    benign: assessment.signals.filter((x) => x.signalType === 'BENIGN_SIGNAL').length
  };
}

/**
 * Adopt the pre-execution classification when the forensic engine called a site
 * benign or unclassified but the pre-execution engine found a concrete pattern.
 */
function adoptClassification(assessment, pe) {
  const peLabel = pe.classification.primary;
  if (['Legitimate', 'Unknown'].includes(peLabel)) return;
  const legacyPrimary = assessment.classification?.primary || '';
  if (!/legitimate|low-risk|unclassified/i.test(legacyPrimary)) return;
  assessment.classification = {
    ...assessment.classification,
    primary: peLabel,
    confidence: pe.classification.confidence,
    secondary: pe.classification.secondary,
    explanation: pe.classification.explanation,
    evidence: (pe.classification.detectedSignals || []).map(signal => ({ signal, strength: 'high' }))
  };
  if (assessment.passport) assessment.passport.primaryClassification = peLabel;
}

/**
 * Rebuild the headline verdict of a legacy assessment when the pre-execution
 * engine finds materially more risk than the legacy engine did.
 */
export function reconcileAssessment(assessment, preExecution) {
  assessment.preExecution = preExecution;
  assessment.sevenDimensions = preExecution.sevenDimensions;
  assessment.governmentVerification = preExecution.governmentVerification;
  assessment.gamblingOrPonzi = preExecution.gamblingOrPonzi;
  assessment.passport = {
    ...assessment.passport,
    verificationToken: preExecution.verificationToken,
    unknownSuspicious: preExecution.scoring.unknownSuspicious,
    governmentVerification: preExecution.governmentVerification
  };

  const legacyScore = assessment.score;
  const peScore = preExecution.scoring.totalScore;
  assessment.engineScores = { forensic: legacyScore, preExecution: peScore };

  adoptClassification(assessment, preExecution);
  mergeEvidence(assessment, preExecution);

  // Determine final score based on government verification and gambling/ponzi rules
  let finalScore = Math.max(legacyScore, peScore);

  if (preExecution.governmentVerification?.isGovt) {
    finalScore = Math.min(12, peScore);
  } else if (preExecution.gamblingOrPonzi?.isDetected) {
    finalScore = Math.max(88, finalScore);
  } else if (preExecution.governmentVerification?.verified === false) {
    finalScore = Math.max(preExecution.governmentVerification.riskFloor || 70, finalScore);
  }

  const level = levelFor(finalScore);
  const pe = preExecution;

  assessment.score = finalScore;
  assessment.risk_level = level;
  if (assessment.riskPillars?.overallRisk) {
    assessment.riskPillars.overallRisk = { ...assessment.riskPillars.overallRisk, score: finalScore, level };
  }

  const peLabel = pe.classification.primary;
  const peIsRiskyClass = !['Legitimate', 'Unknown'].includes(peLabel);

  // Replace the benign pattern label once the score is no longer benign
  if (finalScore >= 30) {
    assessment.detectedPatterns = (assessment.detectedPatterns || []).filter(p => p.id !== 'PAT_BENIGN_LEGIT_COMMERCE');
    if (peIsRiskyClass && !assessment.detectedPatterns.some(p => p.id === 'PAT_PRE_EXECUTION')) {
      assessment.detectedPatterns.unshift({
        id: 'PAT_PRE_EXECUTION',
        pattern: `${peLabel} indicators`,
        category: 'Pre-execution classification',
        confidence: pe.classification.confidence,
        supportingSignals: (pe.classification.detectedSignals || []).slice(0, 4),
        explanation: pe.classification.explanation,
        severity: level
      });
    }
    if (assessment.detectedPatterns.length === 0) {
      assessment.detectedPatterns.push({
        id: 'PAT_UNKNOWN_SUSPICIOUS',
        pattern: 'Unknown but suspicious',
        category: 'Correlated weak signals',
        confidence: 70,
        supportingSignals: pe.scoring.topFactors.map(f => f.signal).slice(0, 4),
        explanation: 'No blacklist match, but several independent weak signals combine into an elevated risk profile.',
        severity: level
      });
    }
    assessment.primaryPattern = assessment.detectedPatterns[0].pattern;
  }

  // Surface the pre-execution drivers as the top reasons
  const peReasons = (pe.scoring.topFactors || []).map(f => ({
    reason: f.signal,
    severity: level === 'LOW' ? 'MEDIUM' : level,
    impact: f.detail,
    sourceType: 'Pre-execution correlation'
  }));
  const existing = (assessment.topReasons || []).filter(r => r.severity !== 'LOW');
  assessment.topReasons = [...peReasons, ...existing].slice(0, 5);

  rebuildNarrative(assessment, pe, level);

  const v = VERDICTS[level];
  if (v) {
    assessment.verdict = v.verdict;
    assessment.verdictExplanation = v.explanation;
    assessment.recommendedAction = { action: v.action, rationale: v.rationale, immediateSteps: v.steps };
  }

  if (Array.isArray(assessment.timeline) && assessment.timeline.length > 0) {
    const last = assessment.timeline[assessment.timeline.length - 1];
    assessment.timeline[assessment.timeline.length - 1] = {
      ...last,
      score: finalScore,
      risk_level: level,
      majorChanges: 'Pre-execution correlation raised the risk profile'
    };
  }

  assessment.passport = {
    ...assessment.passport,
    overallScore: finalScore,
    severity: level,
    verdict: assessment.verdict,
    verdictText: assessment.verdictExplanation,
    recommendedAction: assessment.recommendedAction.action,
    primaryClassification: assessment.classification?.primary,
    fingerprint: `RR-FINGERPRINT-${assessment.id.toUpperCase()}-${finalScore}`
  };

  return assessment;
}

/**
 * Rewrite the withdrawal-risk and trust-gap sections so they agree with the
 * reconciled verdict instead of the forensic engine's lower score.
 */
function rebuildNarrative(assessment, pe, level) {
  const cls = pe.classification.primary;
  const dom = pe.intelligence?.domain || {};
  const identity = pe.intelligence?.identity || {};
  const flagged = pe.intelligence?.infrastructure?.flaggedDomains?.length || 0;
  const isMoney = /ponzi|investment|crypto|financial/i.test(cls);
  const isBetting = /gambl|betting|casino/i.test(cls);
  const isPhish = /phish/i.test(cls);

  // Lift the pillars that the detected pattern actually implicates
  const lift = (key, min) => {
    const p = assessment.riskPillars?.[key];
    if (p && p.score < min) assessment.riskPillars[key] = { ...p, score: min, level: levelFor(min) };
  };
  if (isMoney) {
    lift('regulatoryRisk', 85);
    lift('commercialRisk', 80);
  } else if (isBetting) {
    lift('regulatoryRisk', 80);
    lift('commercialRisk', 60);
  } else if (isPhish) {
    lift('reputationRisk', 80);
    lift('technicalSecurity', 55);
  }

  if (!assessment.withdrawalRisk?.detected && level !== 'LOW') {
    assessment.withdrawalRisk = isPhish
      ? {
          detected: true,
          riskLevel: level,
          summary: 'Anything typed into this site — passwords, OTPs, card or UPI details — can be used to empty your accounts.',
          indicators: [
            'Login or verification page that imitates a known brand',
            'Urgency cues pushing you to "verify" or "update" immediately',
            'Payment or KYC details collected outside the brand’s official domain'
          ],
          conditions: ['Money moved with stolen credentials is rarely recoverable']
        }
      : {
          detected: true,
          riskLevel: level,
          summary: isBetting
            ? 'Deposits are easy, withdrawals are not: expect turnover requirements, delays and frozen balances.'
            : 'High chance your money gets stuck: deposits are frictionless while withdrawals carry fees, taxes or lock-ins.',
          indicators: isBetting
            ? ['Wagering turnover required before winnings can be withdrawn', 'Payouts routed through informal P2P / UPI merchant accounts', 'Operator can void bets or freeze accounts at its discretion']
            : ['“Clearance tax” or “unfreeze fee” demanded before withdrawals', 'Returns paid from new deposits rather than real profit', 'Support goes silent once a withdrawal is requested'],
          conditions: ['No regulator or ombudsman to complain to', identity.messagingOnly ? 'Support only via Telegram/WhatsApp' : 'Operator identity cannot be verified']
        };
  }

  if (!assessment.trustGap || ['NEGLIGIBLE', 'LOW'].includes(assessment.trustGap.gapLevel)) {
    const claim = isMoney
      ? 'Guaranteed daily returns from a safe, regulated investment platform.'
      : isBetting
      ? 'Licensed, trusted betting platform with instant withdrawals.'
      : isPhish
      ? 'Official account security or verification page.'
      : 'A legitimate, established online business.';
    const observed = [
      `Domain is only ${dom.ageDays ?? '?'} days old${dom.whoisPrivacy ? ' and its owner is hidden by WHOIS privacy' : ''}`,
      identity.level ? `Contact transparency is ${identity.level.toLowerCase()} (${identity.transparencyScore}/100)${identity.messagingOnly ? ', support is messaging-only' : ''}` : null,
      flagged ? `${flagged} site(s) sharing its hosting were previously reported` : null,
      pe.intelligence?.threat?.summary?.isClean ? 'Not listed by any threat feed yet — typical for brand-new scam domains' : 'Listed by threat-intelligence feeds'
    ].filter(Boolean);
    assessment.trustGap = {
      claim,
      observed,
      gapLevel: level === 'CRITICAL' ? 'CRITICAL' : level === 'HIGH' ? 'HIGH' : 'MEDIUM',
      verdict: 'What the site claims is not backed by anything we could verify about who runs it or how long it has existed.'
    };
  }
}

/**
 * Run both engines for a URL and return the reconciled assessment.
 */
export async function runFullAssessment(url, options = {}) {
  const target = normalizeTargetUrl(url);
  let liveTelemetry = options.liveTelemetry || null;
  if (!liveTelemetry && !options.demoScenario) {
    try {
      liveTelemetry = await collectLiveTelemetry(target.fullUrl, target.domain);
    } catch (e) {
      console.warn('[runFullAssessment] Live telemetry collection error:', e.message);
    }
  }

  const preExecution = await runPreExecutionScan(url, { ...options, liveTelemetry });
  const assessment = runComprehensiveRiskAssessment(url, { liveTelemetry });
  return reconcileAssessment(assessment, preExecution);
}

/**
 * Reject input that is not a website address (plain words, emails, broken URLs).
 */
export function validateTarget(input) {
  let raw = (input || '').toString().trim();
  if (!raw) return 'Enter a website address, like example.com.';
  // Strip wrapping quotes if user copied with quotes
  raw = raw.replace(/^["']|["']$/g, '').trim();
  if (!raw) return 'Enter a website address, like example.com.';

  const withoutProto = raw.replace(/^https?:\/\//i, '');
  const domainPart = withoutProto.split(/[/?#]/)[0];
  if (/\s/.test(domainPart)) return 'Website addresses cannot contain spaces in the domain name.';
  if (/^[^/]*@/.test(withoutProto)) return 'That looks like an email address. Enter a website address instead.';

  try {
    const { hostname } = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isHost = /^([a-z0-9-_]+\.)+[a-z][a-z0-9-_]{1,62}$/i.test(hostname) || hostname === 'localhost';
    if (!isIPv4 && !isHost) return `"${raw}" is not a valid website address. Try something like example.com.`;
  } catch {
    return `"${raw}" is not a valid website address. Try something like example.com.`;
  }
  return null;
}
