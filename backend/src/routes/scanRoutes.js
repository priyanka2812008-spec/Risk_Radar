import express from 'express';
import { runComprehensiveRiskAssessment } from '../engine/scoringEngine.js';
import { getScans, getScanById, saveScanAssessment, findScan } from '../store/riskStore.js';
import { reconcileAssessment, runFullAssessment, validateTarget } from '../services/assessment.js';
import {
  runPreExecutionScan,
  normalizeTargetUrl,
  DEMO_SCENARIOS
} from '../services/preExecutionScan.js';
import { collectDomainIntelligence } from '../services/domainIntelligence.js';
import { collectThreatIntelligence } from '../services/threatIntelligence.js';
import { analyzeInfrastructure } from '../services/infrastructureAnalysis.js';
import { classifyWebsite } from '../services/websiteClassifier.js';
import { analyzeIdentity } from '../services/identityAnalysis.js';
import { calculateRiskScore } from '../services/riskEngine.js';
import { run7DClassification } from '../services/sevenDimensionsEngine.js';

const router = express.Router();

/**
 * POST /api/scan/7d
 * 7D Website Risk Classification Engine Endpoint
 * Classifies website across 7 independent dimensions and generates
 * normalized signal matrix, cross-dimension correlation, risk score, and evidence.
 */
router.post('/scan/7d', async (req, res) => {
  try {
    const { url, demoMode } = req.body;
    const invalid = validateTarget(url);
    if (invalid) return res.status(400).json({ error: invalid });

    const result = await run7DClassification(url, { demoMode });
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    console.error('[API /scan/7d error]', err);
    res.status(500).json({ error: '7D Classification Engine failure: ' + err.message });
  }
});

/**
 * GET /api/scan/7d/dimensions
 * Metadata describing the 7 dimensions, rules, and scoring logic
 */
router.get('/scan/7d/dimensions', (req, res) => {
  res.json({
    success: true,
    engine: '7D Website Risk Classification Engine',
    dimensions: [
      { id: 'domain', name: 'Domain', weight: 15, description: 'Age, tenure, lookalike pattern, subdomain depth, registrar, TLD risk' },
      { id: 'infrastructure', name: 'Infrastructure', weight: 15, description: 'IP, ASN, hosting, nameservers, SSL, shared infrastructure & neighbor reputation' },
      { id: 'content', name: 'Content', weight: 15, description: 'Safe text analysis, payment forms, legal disclosures, category detection' },
      { id: 'claims', name: 'Claims', weight: 15, description: 'Dedicated analysis of financial & promotional promises, unrealistic ROI, and bonus lures' },
      { id: 'behavior', name: 'Behavior', weight: 15, description: 'Deposit gates, withdrawal locks, credential harvesting, wallet signatures' },
      { id: 'identity', name: 'Identity', weight: 15, description: 'Business credentials, corporate transparency, domain email match, messaging-only support' },
      { id: 'threatIntelligence', name: 'Threat Intelligence', weight: 10, description: 'Multi-provider abstraction (VirusTotal, Web Risk, PhishTank, URLhaus, OpenPhish)' }
    ],
    principles: [
      'Multi-dimensional correlation: Do not rely on single keywords or single APIs',
      'Unknown does not mean safe: Clean threat intelligence with anomalous structural/identity signals triggers elevated caution',
      'Association Detected ≠ Confirmed Malicious: Neighboring infrastructure is contextual evidence, not conclusive guilt'
    ]
  });
});

/**
 * POST /api/scan/pre-execution
 * Primary Pre-Execution Risk Intelligence Pipeline
 * Flow: Target URL -> Multi-Source Intelligence -> Correlation -> Explainable Risk Score -> Classification -> Evidence
 */
router.post('/scan/pre-execution', async (req, res) => {
  try {
    const { url, demoMode, demoScenario } = req.body;
    const invalid = validateTarget(url);
    if (invalid) return res.status(400).json({ error: invalid });

    const preExecutionResult = await runPreExecutionScan(url, { demoMode, demoScenario });

    // Also bridge with legacy scan store so history & reports reflect the scan
    try {
      const assessment = reconcileAssessment(runComprehensiveRiskAssessment(url), preExecutionResult);
      await saveScanAssessment(assessment);
      preExecutionResult.reportScanId = assessment.id;
    } catch (saveErr) {
      console.warn('[PreExecutionScan] Warning saving legacy mirror:', saveErr.message);
    }

    res.status(200).json({
      success: true,
      data: preExecutionResult
    });
  } catch (err) {
    console.error('[API /scan/pre-execution error]', err);
    res.status(500).json({ error: 'Pre-execution intelligence failure: ' + err.message });
  }
});

/**
 * POST /api/analyze-url
 * Dedicated Browser Extension endpoint
 * Automatically analyzes current tab target without manual pasting
 */
router.post('/analyze-url', async (req, res) => {
  try {
    const { url, demoMode } = req.body;
    const invalid = validateTarget(url);
    if (invalid) {
      return res.status(400).json({ error: invalid, code: 'INVALID_URL' });
    }

    const preExecution = await runPreExecutionScan(url, { demoMode });

    // Save scan to persistence/resilient memory mirror
    try {
      await saveScanAssessment(reconcileAssessment(runComprehensiveRiskAssessment(url), preExecution));
    } catch (saveErr) {
      console.warn('[analyze-url] Warning saving legacy mirror:', saveErr.message);
    }

    // Normalize signals into extension evidence groups
    const signalsGrouped = [
      {
        category: 'Domain Intelligence',
        status: preExecution.intelligence.domain.ageDays < 30 ? 'Detected' : 'Not Detected',
        severity: preExecution.intelligence.domain.ageDays < 30 ? 'HIGH' : 'LOW',
        explanation: preExecution.intelligence.domain.ageDays < 30
          ? `Newly registered domain (${preExecution.intelligence.domain.ageDays} days old)`
          : `Established registration tenure (${preExecution.intelligence.domain.ageDays} days old)`,
        source: 'WHOIS / RDAP Registry'
      },
      {
        category: 'Contact Analysis',
        status: preExecution.intelligence.identity.messagingOnly || preExecution.intelligence.identity.level === 'LOW' ? 'Detected' : 'Not Detected',
        severity: preExecution.intelligence.identity.level === 'LOW' ? 'HIGH' : 'LOW',
        explanation: preExecution.intelligence.identity.messagingOnly 
          ? 'Only Telegram/WhatsApp contact available — no verifiable business identity'
          : (preExecution.intelligence.identity.email.domainMatch ? 'Verified corporate domain email match' : 'Unverified third-party contact channels'),
        source: 'Forensic Contact Inspection'
      },
      {
        category: 'Reputation',
        status: preExecution.intelligence.threat.summary.detectedBy > 0 ? 'Detected' : 'Not Detected',
        severity: preExecution.intelligence.threat.summary.detectedBy > 0 ? 'CRITICAL' : 'LOW',
        explanation: preExecution.intelligence.threat.summary.detectedBy > 0
          ? `Flagged by ${preExecution.intelligence.threat.summary.detectedBy} threat intelligence feeds`
          : 'No known threat-intelligence match found (zero blacklist hits)',
        source: 'Threat Intelligence Feeds'
      },
      {
        category: 'Website Content',
        status: preExecution.classification.contentSignals && preExecution.classification.contentSignals.length > 0 ? 'Detected' : 'Not Detected',
        severity: preExecution.scoring.components.behavioralContent.score > 4 ? 'HIGH' : 'LOW',
        explanation: preExecution.classification.detectedSignals?.length > 0
          ? preExecution.classification.detectedSignals.slice(0, 2).join(' • ')
          : (preExecution.classification.primary !== 'Legitimate' ? `Indicators of ${preExecution.classification.primary}` : 'Standard commercial presentation'),
        source: 'Content & Signal Heuristics'
      },
      {
        category: 'Infrastructure',
        status: preExecution.intelligence.infrastructure.flaggedDomains.length > 0 ? 'Detected' : 'Not Detected',
        severity: preExecution.intelligence.infrastructure.flaggedDomains.length > 0 ? 'HIGH' : 'LOW',
        explanation: preExecution.intelligence.infrastructure.flaggedDomains.length > 0
          ? `${preExecution.intelligence.infrastructure.flaggedDomains.length} suspicious domains co-hosted on this infrastructure`
          : `Co-hosted on ASN ${preExecution.intelligence.domain.asn.asn} (${preExecution.intelligence.domain.asn.org})`,
        source: 'Passive DNS & Network Telemetry'
      }
    ];

    // Build extension-tailored response
    res.status(200).json({
      success: true,
      url: preExecution.url,
      domain: preExecution.domain,
      riskScore: preExecution.scoring.totalScore,
      riskLevel: preExecution.scoring.riskLevel,
      riskColor: preExecution.scoring.riskColor,
      statusLabel: preExecution.scoring.statusLabel,
      unknownSuspicious: preExecution.scoring.unknownSuspicious,
      classification: preExecution.classification.primary,
      confidence: preExecution.classification.confidence / 100,
      confidencePercent: preExecution.classification.confidence,
      secondaryClassification: preExecution.classification.secondary,
      explanation: preExecution.classification.explanation,
      signals: signalsGrouped,
      topFactors: preExecution.scoring.topFactors,
      threatIntelligence: {
        summary: preExecution.intelligence.threat.summary,
        providers: preExecution.intelligence.threat.providers
      },
      domainIntelligence: {
        ageDays: preExecution.intelligence.domain.ageDays,
        registrationDate: preExecution.intelligence.domain.registrationDate,
        registrar: preExecution.intelligence.domain.registrar,
        country: preExecution.intelligence.domain.country,
        ipAddress: preExecution.intelligence.domain.ipAddress,
        asn: preExecution.intelligence.domain.asn,
        hostingProvider: preExecution.intelligence.domain.hostingProvider,
        ssl: preExecution.intelligence.domain.ssl
      },
      infrastructure: {
        relatedDomainsCount: preExecution.intelligence.infrastructure.relatedDomains.length,
        flaggedDomainsCount: preExecution.intelligence.infrastructure.flaggedDomains.length,
        flaggedDomains: preExecution.intelligence.infrastructure.flaggedDomains
      },
      contactAnalysis: {
        level: preExecution.intelligence.identity.level,
        transparencyScore: preExecution.intelligence.identity.transparencyScore,
        businessEmailMatch: preExecution.intelligence.identity.email.domainMatch,
        primaryEmail: preExecution.intelligence.identity.email.email,
        phoneDetected: preExecution.intelligence.identity.phone.detected,
        addressDetected: preExecution.intelligence.identity.address.detected,
        messagingOnly: preExecution.intelligence.identity.messagingOnly,
        messagingChannels: preExecution.intelligence.identity.messagingChannels
      },
      recommendation: preExecution.scoring.totalScore >= 60 
        ? 'High risk detected — avoid entering credentials, payments, or personal data.'
        : (preExecution.scoring.totalScore >= 30 
          ? 'Exercise caution — verify business credentials before engaging.' 
          : 'Low observed risk across tested intelligence vectors.'),
      passport: preExecution.passport,
      verificationToken: preExecution.verificationToken,
      scanId: preExecution.scanId,
      timestamp: preExecution.timestamp,
      fullReportUrl: `${process.env.CLIENT_URL || 'http://localhost:5173'}/?scan=${encodeURIComponent(preExecution.domain)}`
    });
  } catch (err) {
    console.error('[API /analyze-url error]', err);
    res.status(500).json({ 
      error: 'Risk Radar intelligence backend failure: ' + err.message,
      code: 'BACKEND_ERROR'
    });
  }
});

/**
 * GET /api/scan/demo-scenarios
 * Returns predefined mock intelligence scenarios for hackathons/demonstrations
 */
router.get('/scan/demo-scenarios', (req, res) => {
  res.json({
    success: true,
    data: DEMO_SCENARIOS
  });
});

/**
 * GET /api/scan/passport/:token
 * Lookup B2B Digital Risk Passport by verification token or scanId
 */
router.get('/scan/passport/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const match = findScan(s => 
      s.id === token || 
      s.preExecution?.verificationToken === token ||
      s.passport?.verificationToken === token ||
      s.domain === token
    );

    if (!match) {
      return res.status(404).json({ error: `No Risk Passport found matching token: ${token}` });
    }

    res.json({
      success: true,
      data: match.preExecution?.passport || match.passport || match
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/domain-intelligence
 * Modular standalone endpoint for domain registration, WHOIS, DNS, SSL, and ASN data
 */
router.post('/domain-intelligence', async (req, res) => {
  try {
    const { url, domain } = req.body;
    const targetDomain = domain || (url ? normalizeTargetUrl(url).domain : null);
    if (!targetDomain) {
      return res.status(400).json({ error: 'Domain or URL parameter is required.' });
    }

    const intel = await collectDomainIntelligence(targetDomain);
    res.json({ success: true, data: intel });
  } catch (err) {
    res.status(500).json({ error: 'Domain intelligence error: ' + err.message });
  }
});

/**
 * POST /api/threat-intelligence
 * Modular standalone endpoint for multi-provider threat intelligence abstraction
 */
router.post('/threat-intelligence', async (req, res) => {
  try {
    const { url, domain, demoMode } = req.body;
    const target = normalizeTargetUrl(url || domain || '');
    const intel = await collectThreatIntelligence(target.fullUrl, target.domain, { demoMode });
    res.json({ success: true, data: intel });
  } catch (err) {
    res.status(500).json({ error: 'Threat intelligence error: ' + err.message });
  }
});

/**
 * POST /api/infrastructure
 * Modular standalone endpoint for infrastructure relationship analysis
 */
router.post('/infrastructure', async (req, res) => {
  try {
    const { url, domain } = req.body;
    const targetDomain = domain || (url ? normalizeTargetUrl(url).domain : null);
    if (!targetDomain) {
      return res.status(400).json({ error: 'Domain or URL parameter is required.' });
    }

    const domainIntel = await collectDomainIntelligence(targetDomain);
    const infra = await analyzeInfrastructure(targetDomain, domainIntel);
    res.json({ success: true, data: infra });
  } catch (err) {
    res.status(500).json({ error: 'Infrastructure analysis error: ' + err.message });
  }
});

/**
 * POST /api/classification
 * Modular standalone endpoint for website pattern and risk classification
 */
router.post('/classification', async (req, res) => {
  try {
    const { url, domain } = req.body;
    const target = normalizeTargetUrl(url || domain || '');
    const domainIntel = await collectDomainIntelligence(target.domain);
    const threatIntel = await collectThreatIntelligence(target.fullUrl, target.domain);
    const classification = classifyWebsite(target.domain, target.fullUrl, domainIntel, threatIntel);
    res.json({ success: true, data: classification });
  } catch (err) {
    res.status(500).json({ error: 'Classification error: ' + err.message });
  }
});

/**
 * POST /api/risk-score
 * Modular standalone endpoint for predictive risk scoring correlation
 */
router.post('/risk-score', async (req, res) => {
  try {
    const { domainIntelligence, threatIntelligence, infrastructure, classification, identity, domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Target domain is required for risk score computation.' });
    }

    const score = calculateRiskScore(
      domainIntelligence,
      threatIntelligence,
      infrastructure,
      classification,
      identity,
      domain
    );
    res.json({ success: true, data: score });
  } catch (err) {
    res.status(500).json({ error: 'Risk calculation error: ' + err.message });
  }
});

/**
 * POST /api/scan
 * Analyze single target URL in real-time
 * (Backward compatible + includes pre-execution intelligence)
 */
router.post('/scan', async (req, res) => {
  try {
    const { url, preExecutionOnly, demoMode } = req.body;
    const invalid = validateTarget(url);
    if (invalid) return res.status(400).json({ error: invalid });

    if (preExecutionOnly) {
      const preExecution = await runPreExecutionScan(url, { demoMode });
      return res.status(200).json({ success: true, data: preExecution });
    }

    // Both engines, reconciled into one verdict
    const assessment = await runFullAssessment(url, { demoMode });
    await saveScanAssessment(assessment);

    res.status(200).json({
      success: true,
      data: assessment
    });
  } catch (err) {
    console.error('[API /scan error]', err);
    res.status(500).json({ error: 'Intelligence scanning failure: ' + err.message });
  }
});

/**
 * POST /api/scan/bulk
 * Analyze array of targets in batch
 */
router.post('/scan/bulk', async (req, res) => {
  try {
    const { urls } = req.body;
    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ error: 'An array of URLs is required for bulk scan.' });
    }

    const maxBatch = 15;
    const targetsToProcess = urls.slice(0, maxBatch);
    const results = [];

    for (const rawUrl of targetsToProcess) {
      if (typeof rawUrl === 'string' && rawUrl.trim()) {
        const invalid = validateTarget(rawUrl);
        if (invalid) {
          results.push({ url: rawUrl, error: invalid });
          continue;
        }
        try {
          const assessment = await runFullAssessment(rawUrl);
          await saveScanAssessment(assessment);
          results.push(assessment);
        } catch (e) {
          results.push({ url: rawUrl, error: e.message });
        }
      }
    }

    res.status(200).json({
      success: true,
      processed: results.length,
      data: results
    });
  } catch (err) {
    res.status(500).json({ error: 'Bulk scanning failure: ' + err.message });
  }
});

/**
 * GET /api/scans
 * Retrieve recent scan history
 */
router.get('/scans', async (req, res) => {
  try {
    const scans = await getScans();
    res.json({ success: true, count: scans.length, data: scans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/scans/:id
 * Retrieve specific scan details
 */
router.get('/scans/:id', async (req, res) => {
  try {
    const scan = await getScanById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Assessment scan record not found.' });
    }
    res.json({ success: true, data: scan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
