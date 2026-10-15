/**
 * Pre-Execution Risk Intelligence Orchestrator
 * 
 * Flow:
 * URL -> Intelligence Sources -> Normalized Signals -> Correlation -> Explainable Risk Score -> Classification -> Evidence
 * 
 * CORE PRINCIPLE:
 * "Known malicious != only risky.
 *  Unknown != safe.
 *  Multiple weak signals can combine into a strong risk indication."
 */

import { collectDomainIntelligence } from './domainIntelligence.js';
import { collectThreatIntelligence } from './threatIntelligence.js';
import { analyzeInfrastructure } from './infrastructureAnalysis.js';
import { classifyWebsite } from './websiteClassifier.js';
import { analyzeIdentity } from './identityAnalysis.js';
import { calculateRiskScore } from './riskEngine.js';
import { run7DClassification } from './sevenDimensionsEngine.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Standardize target input to domain and clean URL
 */
export function normalizeTargetUrl(inputUrl) {
  let cleaned = (inputUrl || '').toString().trim();
  if (!cleaned) cleaned = 'example.com';
  
  // Clean whitespace/newlines
  cleaned = cleaned.replace(/\s+/g, '-');
  
  // Check if protocol exists
  const hasProtocol = /^https?:\/\//i.test(cleaned);
  const fullUrl = hasProtocol ? cleaned : `https://${cleaned}`;
  
  try {
    const parsed = new URL(fullUrl);
    let domain = parsed.hostname.toLowerCase();
    // Strip leading www. if needed for domain analysis, but keep domain intact
    return {
      rawUrl: inputUrl,
      fullUrl,
      domain,
      pathname: parsed.pathname,
      search: parsed.search
    };
  } catch {
    // Basic fallback parsing
    let domain = cleaned.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].toLowerCase();
    return {
      rawUrl: inputUrl,
      fullUrl: `https://${domain}`,
      domain,
      pathname: '/',
      search: ''
    };
  }
}

/**
 * Preset Demo Scenarios for hackathons / offline demonstrations
 */
export const DEMO_SCENARIOS = [
  {
    id: 'unknown-suspicious',
    title: 'Unknown but Suspicious (Core Differentiator)',
    domain: 'instant-bonus-pay.cc',
    url: 'https://instant-bonus-pay.cc/claim-bonus',
    category: 'Gambling / Referral-Based Scheme',
    badge: 'NEW DOMAIN • ZERO THREAT INTEL LISTING • SUSPICIOUS INFRASTRUCTURE',
    description: 'Zero threat-intelligence blacklist hits, registered 2 days ago, Telegram-only support, shared infrastructure with 3 flagged domains.'
  },
  {
    id: 'known-phishing',
    title: 'Known Phishing Domain',
    domain: 'paypal-security-update.fake-auth.xyz',
    url: 'https://paypal-security-update.fake-auth.xyz/verify-login',
    category: 'Phishing',
    badge: 'CRITICAL RISK • MULTI-ENGINE DETECTION',
    description: 'Credential harvesting form imitating financial institution, flagged by VirusTotal & Google Web Risk.'
  },
  {
    id: 'new-gambling',
    title: 'New Online Betting Platform',
    domain: 'bet777-instant-win.online',
    url: 'https://bet777-instant-win.online/sportsbook',
    category: 'Betting / Casino',
    badge: 'HIGH RISK • DEPOSIT & BONUS INCENTIVES',
    description: 'Aggressive deposit prompts, 200% bonus promises, offshore registrar, lack of licensing proof.'
  },
  {
    id: 'ponzi-scheme',
    title: 'High-Yield Investment / Ponzi Scheme',
    domain: 'daily-crypto-roi-1000.top',
    url: 'https://daily-crypto-roi-1000.top/invest',
    category: 'Ponzi Scheme / Crypto Scam',
    badge: 'HIGH RISK • CAPITAL RETENTION TRAP',
    description: 'Guaranteed 5% daily returns, mandatory tier recruitment, withdrawal delay mechanics detected.'
  },
  {
    id: 'legitimate-enterprise',
    title: 'Legitimate Enterprise Website',
    domain: 'stripe.com',
    url: 'https://stripe.com',
    category: 'Legitimate / Financial Infrastructure',
    badge: 'LOW RISK • ESTABLISHED TENURE',
    description: '14+ years domain history, multi-factor identity verification, clean threat intel across all engines.'
  }
];

/**
 * Run Comprehensive Pre-Execution Risk Intelligence Scan
 * Does NOT execute any JavaScript from the target in the user's browser.
 * Safe server-side telemetry aggregation.
 */
export async function runPreExecutionScan(targetInput, options = {}) {
  const startTime = Date.now();
  const target = normalizeTargetUrl(targetInput);
  const domain = target.domain;
  const fullUrl = target.fullUrl;
  
  const isDemo = Boolean(options.demoMode || options.demoScenario);
  
  // 1. Parallel Collection of Intelligence Signals
  // Domain Intelligence + Threat Intelligence
  const [domainIntel, threatIntel] = await Promise.all([
    collectDomainIntelligence(domain),
    collectThreatIntelligence(fullUrl, domain, { demoMode: isDemo })
  ]);
  
  // 2. Infrastructure Relationship Analysis (depends on domain IP & ASN)
  const infraIntel = await analyzeInfrastructure(domain, domainIntel);
  
  // 3. Website Classification (correlates domain + threat + content signals)
  const classification = classifyWebsite(domain, fullUrl, domainIntel, threatIntel);
  
  // 4. Contact & Identity Analysis (checks verifiable company credentials)
  const identityIntel = analyzeIdentity(domain, domainIntel);
  
  // 5. Correlate all Signals into Explainable Predictive Risk Score
  const riskResult = calculateRiskScore(
    domainIntel,
    threatIntel,
    infraIntel,
    classification,
    identityIntel,
    domain
  );
  
  const scanDurationMs = Date.now() - startTime;
  
  // Generate Digital Risk Passport for B2B sharing and verification
  const passport = {
    passportId: `PASSPORT-${riskResult.scanId.toUpperCase()}`,
    verificationToken: riskResult.verificationToken,
    domain,
    fullUrl,
    timestamp: riskResult.timestamp,
    overallScore: riskResult.totalScore,
    riskLevel: riskResult.riskLevel,
    riskColor: riskResult.riskColor,
    statusLabel: riskResult.statusLabel,
    unknownSuspicious: riskResult.unknownSuspicious,
    classification: {
      primary: classification.primary,
      confidence: classification.confidence,
      secondary: classification.secondary
    },
    threatIntelSummary: {
      isClean: threatIntel.summary.isClean,
      detectedBy: threatIntel.summary.detectedBy,
      totalEngines: threatIntel.summary.totalProviders,
      verdictText: threatIntel.summary.text
    },
    infrastructureSummary: {
      ip: domainIntel.ipAddress,
      asn: domainIntel.asn.asn,
      provider: domainIntel.asn.org,
      flaggedDomainsAssociated: infraIntel.flaggedDomains.length,
      associationDetected: infraIntel.flaggedDomains.length > 0
    },
    identitySummary: {
      transparencyLevel: identityIntel.level,
      transparencyScore: identityIntel.transparencyScore,
      businessEmailMatch: identityIntel.email.domainMatch,
      messagingOnly: identityIntel.messagingOnly
    },
    topRiskFactors: riskResult.topFactors,
    positiveFactors: riskResult.positiveFactors,
    complianceStatus: riskResult.totalScore <= 20 ? 'COMPLIANT' : (riskResult.totalScore <= 60 ? 'REVIEW_REQUIRED' : 'PROHIBITED')
  };

  // Structured response adhering directly to the user requirements
  return {
    success: true,
    scanId: riskResult.scanId,
    verificationToken: riskResult.verificationToken,
    url: fullUrl,
    domain,
    timestamp: riskResult.timestamp,
    durationMs: scanDurationMs,
    demoMode: isDemo || threatIntel.demoMode,
    
    // Core Scoring & Classification (Separated Confidence from Risk Score!)
    scoring: {
      totalScore: riskResult.totalScore,
      riskLevel: riskResult.riskLevel,
      riskColor: riskResult.riskColor,
      riskDescription: riskResult.riskDescription,
      statusLabel: riskResult.statusLabel,
      unknownSuspicious: riskResult.unknownSuspicious,
      description: riskResult.description,
      components: riskResult.components,
      topFactors: riskResult.topFactors,
      positiveFactors: riskResult.positiveFactors
    },
    
    classification: {
      primary: classification.primary,
      confidence: classification.confidence,
      secondary: classification.secondary,
      explanation: classification.explanation,
      detectedSignals: classification.detectedSignals,
      contentSignals: classification.contentSignals
    },
    
    // Modular Intelligence Telemetry
    intelligence: {
      domain: domainIntel,
      threat: threatIntel,
      infrastructure: infraIntel,
      identity: identityIntel
    },

    // 7D Website Risk Classification Engine
    sevenDimensions: await run7DClassification(fullUrl, { demoMode: isDemo }),
    
    // Digital Risk Passport (B2B shareable compliance artifact)
    passport
  };
}
