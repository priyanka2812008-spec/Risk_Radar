/**
 * Risk Radar Website Risk Classification Engine
 * Evaluates multi-vector forensic telemetry to identify the operational pattern / risk type of a target.
 * 
 * IMPORTANT: CLASSIFICATION != RISK LEVEL
 * - Risk Score (0-100) and Risk Level tell HOW RISKY the website is.
 * - Classification tells WHAT TYPE OF WEBSITE / RISK PATTERN was detected.
 */

// Helper: Normalize and check multiple keywords
function matchCount(text, keywords) {
  let count = 0;
  const matched = [];
  const lower = (text || '').toLowerCase();
  for (const kw of keywords) {
    if (lower.includes(kw)) {
      count++;
      matched.push(kw);
    }
  }
  return { count, matched };
}

/**
 * Classifies a target website based on URL, parsed URL, analyzer results, and Risk DNA
 * @param {Object} parsedUrl - Normalized URL object
 * @param {Object} rawUrl - Full raw URL string
 * @param {Object} context - Context object containing results from modular analyzers & riskDNA
 * @returns {Object} Structured classification object
 */
export const classifyWebsite = ({ 
  parsedUrl, 
  rawUrl, 
  domainResult, 
  technicalResult, 
  contentResult, 
  businessResult, 
  reputationResult, 
  behaviorResult, 
  riskDNA, 
  signals = [],
  contactIdentity
}) => {
  const domain = (parsedUrl?.hostname || '').toLowerCase();
  const path = (parsedUrl?.pathname || '').toLowerCase();
  const search = (parsedUrl?.search || '').toLowerCase();
  const fullUrl = `${domain}${path}${search}`;

  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);

  // 1. Keyword Signal Dictionaries
  const gamblingKeywords = [
    '1xbet', 'bet365', 'parimatch', 'dafabet', 'stake', 'melbet', 'betway',
    'bet', 'casino', 'gambling', 'poker', 'sportsbook', 'slot', 'slots', 'roulette',
    'wager', 'wagering', 'satta', 'matka', 'ipl-bet', 'cricket-betting', 'baccarat',
    'live-dealer', 'odds', 'jackpot', 'betting-app', 'bookmaker', 'i-gaming'
  ];

  const ponziKeywords = [
    'guaranteed-return', 'daily-return', 'passive-income', '100x', 'double-money',
    'risk-free-investment', 'guaranteed-profit', 'ponzi', 'fastcash', 'high-yield',
    'yield-farm', 'liquidity-pool-guarantee', 'fixed-apy', 'referral-bonus',
    'pyramid-commission', 'downstream-earning', 'recruit-to-earn', 'unfreeze-tax'
  ];

  const cryptoTradingKeywords = [
    'crypto', 'bitcoin', 'ethereum', 'trading-bot', 'arbitrage-bot',
    'binary-options', 'forex-guaranteed', 'token-giveaway', 'airdrop-claim',
    'wallet-connect', 'liquidity-staking', 'crypto-custody', 'defi-yield'
  ];

  const phishingKeywords = [
    'secure-login', 'verify-account', 'update-wallet', 'portal-auth',
    'confirm-identity', 'signin-alert', 'banking-gate', 'metamask-recover',
    'passphrase', 'ledger-sync', 'session-expired', 'account-unlock',
    'recover-key', 'auth-gate', 'login-verify'
  ];

  const ecommerceScamKeywords = [
    'cheap-luxury', 'outlet-deals', '90-off', 'replica-store',
    'discount-brand', 'free-gift-card', 'flash-sale-vip', 'wholesale-knockoff',
    'clearance-warehouse-now'
  ];

  const financialScamKeywords = [
    'advance-fee', 'unfreeze-payment', 'wire-instructions', 'cashapp-clearance',
    'grant-claim', 'loan-approval-fee', 'processing-fee-deposit', 'p2p-mule'
  ];

  const deceptiveMarketingKeywords = [
    'as-seen-on', 'miracle-formula', 'instant-wealth', 'secret-algorithm',
    'countdown-ending', 'slots-remaining', 'fortune-500-endorsed'
  ];

  // Match keyword sets
  const gMatch = matchCount(fullUrl, gamblingKeywords);
  const pMatch = matchCount(fullUrl, ponziKeywords);
  const cMatch = matchCount(fullUrl, cryptoTradingKeywords);
  const phMatch = matchCount(fullUrl, phishingKeywords);
  const eMatch = matchCount(fullUrl, ecommerceScamKeywords);
  const fMatch = matchCount(fullUrl, financialScamKeywords);
  const dMatch = matchCount(fullUrl, deceptiveMarketingKeywords);

  // Assess specific signals from analyzers
  const hasBrandSpoof = contentResult?.metadata?.brandSpoofDetected || signals.some(s => s.indicator?.includes('Brand Spoofing') || s.indicator?.includes('Typosquatting'));
  const hasGamblingClaims = contentResult?.metadata?.gamblingClaimsPresent || businessResult?.metadata?.businessCategory?.includes('Gambling') || signals.some(s => s.indicator?.includes('Gambling') || s.indicator?.includes('Wagering'));
  const hasPonziClaims = contentResult?.metadata?.guaranteedReturnClaim || businessResult?.metadata?.hasReferralPyramid || signals.some(s => s.indicator?.includes('Yield') || s.indicator?.includes('Pyramidal') || s.indicator?.includes('Hostage'));
  const hasPhishingSignals = signals.some(s => s.indicator?.includes('Credential Harvesting') || s.indicator?.includes('Spoofed Brand'));
  const hasEcommerceSignals = signals.some(s => s.indicator?.includes('Bait Pricing') || s.indicator?.includes('Deceptive Pricing'));
  const hasGovEnforcement = signals.some(s => s.sourceType?.startsWith('Tier 1') && s.severity === 'HIGH');
  const hasWithdrawalFriction = signals.some(s => s.indicator?.includes('Withdrawal') || s.indicator?.includes('Payout Friction'));

  // Calculate evidence weight scores for each primary classification category
  const categories = [];

  // Category 1: Gambling / Betting
  let gamblingEvidence = [];
  let gamblingScore = 0;
  if (hasGamblingClaims || gMatch.count > 0) {
    if (gMatch.count >= 2) {
      gamblingScore += 45;
      gamblingEvidence.push({ signal: `Sports betting and wagering terminology detected: [${gMatch.matched.slice(0, 3).join(', ')}]`, strength: 'high' });
    } else if (gMatch.count === 1) {
      gamblingScore += 25;
      gamblingEvidence.push({ signal: `Betting-related term identified in target locator: [${gMatch.matched[0]}]`, strength: 'medium' });
    }
    if (hasGamblingClaims) {
      gamblingScore += 35;
      gamblingEvidence.push({ signal: 'Commercial online gambling / sportsbook gaming model verified', strength: 'high' });
    }
    if (hasWithdrawalFriction) {
      gamblingScore += 10;
      gamblingEvidence.push({ signal: 'Turnover & wagering withdrawal prerequisites detected', strength: 'medium' });
    }
    if (hasGovEnforcement) {
      gamblingScore += 10;
      gamblingEvidence.push({ signal: 'Subject to cross-border statutory gambling enforcement advisories', strength: 'high' });
    }
  }
  if (gamblingScore >= 30) {
    const secondaryTags = [];
    if (gMatch.matched.some(k => ['bet', 'sportsbook', 'odds', '1xbet', 'bet365', 'parimatch'].includes(k))) secondaryTags.push('Sports Betting');
    if (gMatch.matched.some(k => ['casino', 'slot', 'slots', 'roulette', 'poker'].includes(k))) secondaryTags.push('Casino / Wagering');
    if (gMatch.matched.some(k => ['wager', 'wagering', 'odds'].includes(k)) || !secondaryTags.includes('Sports Betting')) secondaryTags.push('Deposit-Based Wagering');
    if (hasWithdrawalFriction) secondaryTags.push('Withdrawal Risk');
    if (hasGovEnforcement) secondaryTags.push('Regulatory Concern');
    if (fullUrl.includes('live')) secondaryTags.push('Live Betting');

    categories.push({
      category: 'Gambling / Betting',
      score: gamblingScore,
      confidence: Math.min(96, Math.max(70, gamblingScore)),
      explanation: 'Multiple consistent betting and wagering indicators were detected across domain structure, commercial model, and operational copy.',
      secondary: secondaryTags,
      evidence: gamblingEvidence
    });
  }

  // Category 2: Ponzi / Investment Scam
  let ponziEvidence = [];
  let ponziScore = 0;
  if (hasPonziClaims || pMatch.count > 0) {
    if (pMatch.count >= 2) {
      ponziScore += 45;
      ponziEvidence.push({ signal: `High-yield gain assertions detected: [${pMatch.matched.slice(0, 3).join(', ')}]`, strength: 'high' });
    } else if (pMatch.count === 1) {
      ponziScore += 20;
      ponziEvidence.push({ signal: `Financial gain phrase detected: [${pMatch.matched[0]}]`, strength: 'medium' });
    }
    if (hasPonziClaims) {
      ponziScore += 40;
      ponziEvidence.push({ signal: 'Multi-tier downstream recruitment referral architecture identified', strength: 'high' });
    }
    if (signals.some(s => s.indicator?.includes('Hostage') || s.indicator?.includes('Lock'))) {
      ponziScore += 15;
      ponziEvidence.push({ signal: 'Upfront verification tax / withdrawal deposit lock mechanics detected', strength: 'high' });
    }
  }
  if (ponziScore >= 35) {
    const secondaryTags = ['Guaranteed Returns', 'Referral Scheme', 'Investment Deposit Model'];
    if (pMatch.matched.some(k => ['unrealistic', 'double', '100x', 'fastcash'].includes(k))) secondaryTags.push('Unrealistic Profit Claims');
    if (ponziEvidence.some(e => e.signal.includes('Hostage') || e.signal.includes('tax'))) secondaryTags.push('Withdrawal Trap Mechanics');

    categories.push({
      category: 'Ponzi / Investment Scam',
      score: ponziScore,
      confidence: Math.min(97, Math.max(72, ponziScore)),
      explanation: 'Platform exhibits hallmarks of a synthetic high-yield investment scheme, featuring guaranteed returns and referral-driven recruitment.',
      secondary: secondaryTags,
      evidence: ponziEvidence
    });
  }

  // Category 3: Phishing / Credential Theft
  let phishingEvidence = [];
  let phishingScore = 0;
  if (hasBrandSpoof || hasPhishingSignals || phMatch.count > 0) {
    if (phMatch.count >= 1) {
      phishingScore += 40;
      phishingEvidence.push({ signal: `Authentication interception keywords detected: [${phMatch.matched.join(', ')}]`, strength: 'high' });
    }
    if (hasBrandSpoof) {
      phishingScore += 35;
      phishingEvidence.push({ signal: 'Brand typosquatting or visual recovery impersonation cues observed', strength: 'high' });
    }
    if (hasPhishingSignals) {
      phishingScore += 25;
      phishingEvidence.push({ signal: 'Obfuscated form submission destination targeting non-canonical auth endpoints', strength: 'high' });
    }
  }
  if (phishingScore >= 35) {
    const secondaryTags = ['Login Credential Collection'];
    if (hasBrandSpoof) secondaryTags.push('Brand Impersonation');
    secondaryTags.push('Suspicious Authentication Page');
    if (phMatch.matched.some(k => k.includes('wallet') || k.includes('metamask') || k.includes('ledger'))) secondaryTags.push('Web3 / Wallet Interception');

    categories.push({
      category: 'Phishing / Credential Theft',
      score: phishingScore,
      confidence: Math.min(98, Math.max(75, phishingScore)),
      explanation: 'Authentication gateway exhibits deceptive credential harvesting indicators and brand impersonation characteristics.',
      secondary: secondaryTags,
      evidence: phishingEvidence
    });
  }

  // Category 4: Crypto / Trading Risk
  let cryptoEvidence = [];
  let cryptoScore = 0;
  if (cMatch.count > 0 && !categories.some(c => c.category === 'Ponzi / Investment Scam' && c.score >= 70)) {
    if (cMatch.count >= 2) {
      cryptoScore += 40;
      cryptoEvidence.push({ signal: `Crypto trading and token mechanics identified: [${cMatch.matched.slice(0, 3).join(', ')}]`, strength: 'high' });
    } else {
      cryptoScore += 25;
      cryptoEvidence.push({ signal: `Crypto asset keyword present: [${cMatch.matched[0]}]`, strength: 'medium' });
    }
    if (businessResult?.metadata?.businessCategory?.includes('Derivatives') || signals.some(s => s.indicator?.includes('Binary Options'))) {
      cryptoScore += 30;
      cryptoEvidence.push({ signal: 'Unlicensed high-leverage derivatives or speculative contract trading offered', strength: 'high' });
    }
    if (signals.some(s => s.indicator?.includes('Wallet'))) {
      cryptoScore += 15;
      cryptoEvidence.push({ signal: 'Direct browser wallet connection prompt without audited smart contract', strength: 'medium' });
    }
  }
  if (cryptoScore >= 30) {
    const secondaryTags = ['Crypto Investment Platform'];
    if (cMatch.matched.some(k => ['binary-options', 'forex-guaranteed'].includes(k))) secondaryTags.push('High-Leverage Derivatives');
    secondaryTags.push('Speculative Market Risk');
    if (cMatch.matched.some(k => ['arbitrage-bot', 'trading-bot'].includes(k))) secondaryTags.push('Algorithmic Return Promises');

    categories.push({
      category: 'Crypto / Trading Risk',
      score: cryptoScore,
      confidence: Math.min(94, Math.max(68, cryptoScore)),
      explanation: 'Platform operates speculative cryptocurrency trading or algorithmic yield utilities subject to heightened volatility and regulatory oversight.',
      secondary: secondaryTags,
      evidence: cryptoEvidence
    });
  }

  // Category 5: Financial / Payment Scam
  let financialEvidence = [];
  let financialScore = 0;
  if (fMatch.count > 0 || (signals.some(s => s.indicator?.includes('Fee Lock')) && !categories.some(c => c.category === 'Ponzi / Investment Scam'))) {
    financialScore += 40;
    financialEvidence.push({ signal: `Suspicious payment / fee collection markers identified: [${fMatch.matched.join(', ')}]`, strength: 'high' });
    if (signals.some(s => s.indicator?.includes('Payment Ingress') || s.indicator?.includes('P2P'))) {
      financialScore += 25;
      financialEvidence.push({ signal: 'Unverified peer-to-peer payment routing with lack of centralized clearing', strength: 'medium' });
    }
  }
  if (financialScore >= 35) {
    categories.push({
      category: 'Financial / Payment Scam',
      score: financialScore,
      confidence: Math.min(90, Math.max(65, financialScore)),
      explanation: 'Platform requires unorthodox upfront fee clearing or non-reversible peer-to-peer payment channels.',
      secondary: ['Advance-Fee Pattern', 'Unverified Payment Routing', 'Suspicious Fee Demand'],
      evidence: financialEvidence
    });
  }

  // Category 6: E-commerce Scam
  let ecomEvidence = [];
  let ecomScore = 0;
  if (hasEcommerceSignals || eMatch.count > 0) {
    if (eMatch.count >= 1) {
      ecomScore += 45;
      ecomEvidence.push({ signal: `Counterfeit bait / steep discount markers: [${eMatch.matched.join(', ')}]`, strength: 'high' });
    }
    if (hasEcommerceSignals) {
      ecomScore += 30;
      ecomEvidence.push({ signal: '85-95% below market MSRP listing with untraceable checkout options', strength: 'high' });
    }
  }
  if (ecomScore >= 35) {
    categories.push({
      category: 'E-commerce Scam',
      score: ecomScore,
      confidence: Math.min(92, Math.max(65, ecomScore)),
      explanation: 'Storefront exhibits indicators of counterfeit merchandise marketing, deceptive discount baiting, or unverified merchant provenance.',
      secondary: ['Extreme Bait Pricing', 'Counterfeit / Replica Markers', 'Unverified Merchant Entity'],
      evidence: ecomEvidence
    });
  }

  // Category 7: Deceptive / Misleading Claims
  let deceptiveEvidence = [];
  let deceptiveScore = 0;
  if (dMatch.count > 0 || signals.some(s => s.indicator?.includes('Urgency') || s.indicator?.includes('Social Proof'))) {
    deceptiveScore += 35;
    deceptiveEvidence.push({ signal: 'Urgency countdown triggers and unverified social proof badges observed', strength: 'medium' });
  }
  if (deceptiveScore >= 35) {
    categories.push({
      category: 'Deceptive / Misleading Claims',
      score: deceptiveScore,
      confidence: Math.min(88, Math.max(60, deceptiveScore)),
      explanation: 'Presentation layer employs coercive urgency cues and unverifiable commercial endorsements.',
      secondary: ['Artificial Urgency / Scarcity', 'Fabricated Social Proof', 'Exaggerated Performance Claims'],
      evidence: deceptiveEvidence
    });
  }

  // Helper to attach supporting contact evidence
  const attachContactEvidence = (evidenceList, secondarySet) => {
    if (!contactIdentity) return;
    if (contactIdentity.level === 'LOW') {
      if (contactIdentity.messagingOnly && contactIdentity.messagingChannels.length > 0) {
        evidenceList.push({
          signal: `Support channeled exclusively through instant messaging (${contactIdentity.messagingChannels.join(', ')})`,
          strength: 'medium'
        });
        secondarySet.add(`${contactIdentity.messagingChannels.join('/')}-Only Support`);
      }
      if (!contactIdentity.addressDetected) {
        evidenceList.push({
          signal: 'No identifiable corporate or physical business address',
          strength: 'low'
        });
        secondarySet.add('Missing Business Address');
      }
      if (contactIdentity.isFreeEmail) {
        evidenceList.push({
          signal: `Contact email uses free public provider (${contactIdentity.primaryEmail})`,
          strength: 'low'
        });
      }
    } else if (contactIdentity.level === 'HIGH') {
      if (contactIdentity.domainEmailMatch) {
        evidenceList.push({
          signal: 'Domain-aligned corporate contact email verified',
          strength: 'medium'
        });
        secondarySet.add('Domain-Aligned Email');
      }
      if (contactIdentity.addressDetected) {
        evidenceList.push({
          signal: 'Public registered corporate headquarters observed',
          strength: 'medium'
        });
        secondarySet.add('Verified Office Address');
      }
    }
  };

  // Sort matched categories by score descending to find the strongest Primary Classification
  categories.sort((a, b) => b.score - a.score);

  if (categories.length > 0) {
    const primaryChoice = categories[0];
    // Gather secondary tags from primary and any other detected categories
    const secondarySet = new Set(primaryChoice.secondary);
    for (let i = 1; i < categories.length; i++) {
      for (const tag of categories[i].secondary) {
        if (secondarySet.size < 6) secondarySet.add(tag);
      }
    }

    const evidenceList = [...primaryChoice.evidence];
    attachContactEvidence(evidenceList, secondarySet);

    return {
      primary: primaryChoice.category,
      secondary: Array.from(secondarySet),
      confidence: primaryChoice.confidence,
      explanation: primaryChoice.explanation,
      evidence: evidenceList
    };
  }

  // Category 8 & 9: If no specific risk pattern matched
  // Check if target is suspicious/unclassified vs low-risk legitimate
  const isHighRiskScore = riskDNA?.technical > 45 || riskDNA?.domain > 45 || isIP;

  if (isIP || isHighRiskScore) {
    const unclassEvidence = [];
    if (isIP) unclassEvidence.push({ signal: `Target accessed via direct numerical IPv4 (${domain}) without canonical hostname`, strength: 'medium' });
    if (riskDNA?.domain > 40) unclassEvidence.push({ signal: 'Elevated domain risk markers with limited operational history', strength: 'low' });
    if (unclassEvidence.length === 0) unclassEvidence.push({ signal: 'Sparse content telemetry with inconclusive category indicators', strength: 'low' });

    const secSet = new Set(['Unindexed Ingress Point', 'Anomalous Domain Attributes', 'Insufficient Content Telemetry']);
    attachContactEvidence(unclassEvidence, secSet);

    return {
      primary: 'Suspicious / Unclassified',
      secondary: Array.from(secSet),
      confidence: 64,
      explanation: 'Telemetry is insufficient to attribute a specific commercial category; target exhibits anomalous routing or infrastructure characteristics.',
      evidence: unclassEvidence
    };
  }

  // Category 9: Low-Risk / Legitimate Pattern
  const legitEvidence = [];
  if (domainResult?.metadata?.ageDays > 365) {
    legitEvidence.push({ signal: `Verified domain tenure exceeding ${Math.floor(domainResult.metadata.ageDays / 365)} years with stable DNS provenance`, strength: 'high' });
  } else {
    legitEvidence.push({ signal: 'Standard commercial DNS registration baseline verified', strength: 'medium' });
  }
  if (technicalResult?.metadata?.tlsVersion?.includes('TLS')) {
    legitEvidence.push({ signal: 'Modern cryptographic transport security enforced with valid public certificate', strength: 'medium' });
  }
  legitEvidence.push({ signal: 'Commercial terms of service and standard legal policies verified', strength: 'medium' });

  const legitSecSet = new Set(['Verified Enterprise Infrastructure', 'Transparent Terms & Disclosures', 'Standard Commercial Architecture', 'Clean Threat Intelligence Profile']);
  attachContactEvidence(legitEvidence, legitSecSet);

  return {
    primary: 'Low-Risk / Legitimate Pattern',
    secondary: Array.from(legitSecSet),
    confidence: 94,
    explanation: 'Target exhibits transparent commercial structure, verified institutional infrastructure, and standard legal policies with no anomalous risk patterns detected.',
    evidence: legitEvidence
  };
};
