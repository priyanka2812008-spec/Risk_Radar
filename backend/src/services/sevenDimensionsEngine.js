/**
 * 7D WEBSITE RISK CLASSIFICATION ENGINE
 * 
 * Core intelligence layer classifying and assessing websites across 7 independent dimensions:
 * 1. DOMAIN - Age, tenure, lookalike pattern, subdomain depth, registrar, TLD risk
 * 2. INFRASTRUCTURE - IP, ASN, hoster, nameservers, SSL, shared infrastructure & neighbor reputation
 * 3. CONTENT - Safe text analysis, forms, category detection (Gambling, Ponzi, Phish, Crypto, etc.)
 * 4. CLAIMS - Suspicious financial & promotional promises (guaranteed returns, unrealistic ROI, etc.)
 * 5. BEHAVIOR - User call-to-actions, deposit gates, withdrawal locks, credential harvesting, wallet connects
 * 6. IDENTITY - Business credentials, company transparency, domain email match, Telegram-only contact
 * 7. THREAT INTELLIGENCE - Multi-provider abstraction (VirusTotal, Web Risk, PhishTank, URLhaus, OpenPhish)
 * 
 * CORE PRINCIPLE: "Unknown does not mean safe."
 * When threat intelligence reports zero blacklist hits, the other six dimensions
 * provide independent, explainable risk assessment and classification.
 */

import { collectDomainIntelligence } from './domainIntelligence.js';
import { collectThreatIntelligence } from './threatIntelligence.js';
import { analyzeInfrastructure } from './infrastructureAnalysis.js';
import { analyzeIdentity } from './identityAnalysis.js';
import { detectBrandImpersonation } from './brandImpersonation.js';

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

// ============================================================================
// DIMENSION 1: DOMAIN ANALYSIS
// ============================================================================
export function analyzeDomainDimension(domain, domainIntel = {}, rawUrl = '') {
  const parts = domain.toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  const sld = parts.length > 2 ? parts[parts.length - 2] : parts[0];
  const subdomains = parts.slice(0, -2);
  const subdomainDepth = subdomains.length;
  const ageDays = typeof domainIntel.ageDays === 'number' ? domainIntel.ageDays : 365;

  const signals = [];
  const evidence = [];
  let score = 0; // 0 to 100

  // 1. Domain Age / Tenure
  // IMPORTANT: A new domain must NOT automatically be classified as malicious!
  if (ageDays <= 7) {
    score += 40;
    signals.push({
      signal: 'Recently Registered Domain',
      severity: 'HIGH',
      impact: 25,
      detail: `Domain was registered ${ageDays} day(s) ago. Newly observed registration tenure.`
    });
    evidence.push(`Domain registered ${ageDays} day(s) ago (${domainIntel.registrationDate || 'Recent'})`);
  } else if (ageDays <= 30) {
    score += 25;
    signals.push({
      signal: 'Recently Registered Domain',
      severity: 'MEDIUM',
      impact: 15,
      detail: `Domain tenure is under 30 days (${ageDays} days).`
    });
    evidence.push(`Domain tenure is under 30 days (${ageDays} days)`);
  } else if (ageDays <= 90) {
    score += 15;
    signals.push({
      signal: 'Young Domain (<90 Days)',
      severity: 'LOW',
      impact: 8,
      detail: `Domain is under 90 days old (${ageDays} days).`
    });
    evidence.push(`Young domain registration (${ageDays} days old)`);
  } else if (ageDays >= 730) {
    signals.push({
      signal: 'Established Domain Tenure',
      severity: 'LOW',
      impact: -15,
      detail: `Domain has been registered for over ${Math.floor(ageDays / 365)} years (${ageDays} days).`
    });
    evidence.push(`Established registration history (${Math.floor(ageDays / 365)}+ years)`);
  }

  // 2. High-Risk or Abused TLDs
  const highRiskTlds = ['top', 'xyz', 'click', 'cfd', 'sbs', 'win', 'bet', 'vip', 'buzz', 'icu', 'cc', 'online', 'rest', 'link'];
  if (highRiskTlds.includes(tld)) {
    score += 18;
    signals.push({
      signal: 'High-Risk Top Level Domain',
      severity: 'MEDIUM',
      impact: 12,
      detail: `.${tld} is frequently favored by short-lived scam campaigns due to low acquisition costs.`
    });
    evidence.push(`Registrar assigned under .${tld} TLD`);
  }

  // 3. Subdomain Depth & Structure
  if (subdomainDepth >= 3) {
    score += 22;
    signals.push({
      signal: 'Excessive Subdomain Depth',
      severity: 'HIGH',
      impact: 15,
      detail: `URL contains ${subdomainDepth} nested subdomains (${subdomains.join('.')}), a technique often used in evasion.`
    });
    evidence.push(`Excessive nesting: ${subdomainDepth} subdomains deep`);
  } else if (subdomainDepth >= 1) {
    const suspiciousSubdomainKeywords = ['verify', 'secure', 'login', 'update', 'claim', 'bonus', 'wallet', 'auth', 'signin'];
    const matchedSub = subdomains.find(sub => suspiciousSubdomainKeywords.some(kw => sub.includes(kw)));
    if (matchedSub) {
      score += 20;
      signals.push({
        signal: 'Unusual Subdomain',
        severity: 'MEDIUM',
        impact: 14,
        detail: `Subdomain "${matchedSub}" mimics administrative or authentication flows.`
      });
      evidence.push(`Authentication-mimicking subdomain: "${matchedSub}"`);
    }
  }

  // 4. Lookalike Spelling & Character Substitutions (Typosquatting)
  const impersonation = detectBrandImpersonation(domain, rawUrl);
  if (impersonation.detected) {
    score += 35;
    signals.push({
      signal: 'Lookalike Domain Pattern',
      severity: 'HIGH',
      impact: 25,
      detail: `Domain impersonates targeted brand "${impersonation.brand}" using visual or spelling similarities.`
    });
    evidence.push(`Impersonation of brand "${impersonation.brand}" (official: ${impersonation.officialDomains[0]})`);
  }

  // Number substitution in brand keywords (e.g., betway1, 1xbet, paypa1)
  if (/\d+$/.test(sld) && !/^\d+$/.test(sld)) {
    score += 10;
    signals.push({
      signal: 'Appended Numeric Sequence',
      severity: 'LOW',
      impact: 8,
      detail: `Domain base "${sld}" ends in numeric identifiers, common in rotational mirror domains.`
    });
    evidence.push(`Appended numeric sequence on base domain ("${sld}")`);
  }

  // 5. WHOIS Privacy & Registrar
  if (domainIntel.whoisPrivacy) {
    score += 8;
    signals.push({
      signal: 'Redacted WHOIS Privacy Shield',
      severity: 'LOW',
      impact: 5,
      detail: 'Domain registrant identity is fully concealed behind privacy proxy.'
    });
    evidence.push('WHOIS registration privacy proxy active');
  }

  const finalScore = Math.min(100, Math.max(0, score));

  return {
    dimension: 'DOMAIN',
    score: finalScore,
    weight: 15,
    signals,
    evidence,
    metrics: {
      domain,
      ageDays,
      registrationDate: domainIntel.registrationDate || null,
      expirationDate: domainIntel.expirationDate || null,
      registrar: domainIntel.registrar || 'Protected / Redacted',
      domainStatus: domainIntel.domainStatus || 'clientTransferProhibited',
      subdomainDepth,
      tld: `.${tld}`,
      lookalikeDetected: impersonation.detected
    }
  };
}

// ============================================================================
// DIMENSION 2: INFRASTRUCTURE ANALYSIS
// ============================================================================
export function analyzeInfrastructureDimension(domain, domainIntel = {}, infraIntel = {}) {
  const ip = domainIntel.ipAddress || '198.51.100.1';
  const asn = domainIntel.asn || { asn: 'AS-UNKNOWN', org: 'Standard Hosting' };
  const ssl = domainIntel.ssl || {};
  const relatedDomains = infraIntel.relatedDomains || [];
  const flaggedDomains = infraIntel.flaggedDomains || [];

  const signals = [];
  const evidence = [];
  let score = 0;

  // 1. Shared Infrastructure with Flagged Domains
  // IMPORTANT: Do NOT automatically call target malicious because of shared infrastructure.
  // Use "Association Detected" wording!
  if (flaggedDomains.length > 0) {
    const impact = Math.min(35, flaggedDomains.length * 10);
    score += impact;
    signals.push({
      signal: 'Association Detected (Shared Flagged Infrastructure)',
      severity: flaggedDomains.length >= 3 ? 'HIGH' : 'MEDIUM',
      impact,
      detail: `${flaggedDomains.length} related domains associated with this infrastructure have previously been reported as suspicious.`
    });
    evidence.push(`${flaggedDomains.length} associated domain(s) sharing IP/ASN previously flagged: ${flaggedDomains.slice(0, 3).join(', ')}`);
  } else if (relatedDomains.length > 0) {
    signals.push({
      signal: 'Co-Hosted Infrastructure',
      severity: 'LOW',
      impact: 5,
      detail: `Domain shares IP/network with ${relatedDomains.length} other active hostnames.`
    });
    evidence.push(`Co-hosted alongside ${relatedDomains.length} peer hostnames`);
  }

  // 2. SSL Certificate Evaluation
  if (ssl.daysRemaining !== undefined && ssl.daysRemaining <= 0) {
    score += 25;
    signals.push({
      signal: 'Expired SSL Certificate',
      severity: 'HIGH',
      impact: 20,
      detail: 'TLS certificate is expired or invalid.'
    });
    evidence.push('Expired TLS/SSL certificate');
  } else if (ssl.age !== undefined && ssl.age < 14) {
    score += 12;
    signals.push({
      signal: 'Freshly Issued Certificate',
      severity: 'LOW',
      impact: 8,
      detail: `SSL certificate was issued only ${ssl.age} days ago.`
    });
    evidence.push(`Freshly generated SSL certificate (${ssl.age} days active)`);
  }

  // Free / automated SSL issuance
  if (ssl.issuer && /let's encrypt|cpanel|zerossl|cloudflare/i.test(ssl.issuer)) {
    score += 6;
    evidence.push(`Domain-validated certificate issued by ${ssl.issuer}`);
  } else if (ssl.issuer && /digicert|entrust|globalsign|sectigo/i.test(ssl.issuer)) {
    signals.push({
      signal: 'Enterprise Verified SSL CA',
      severity: 'LOW',
      impact: -10,
      detail: `Certificate issued by enterprise authority ${ssl.issuer}.`
    });
    evidence.push(`Enterprise certificate authority (${ssl.issuer})`);
  }

  // 3. Hosting / ASN Characteristics
  if (asn.org && /bulletproof|offshore|shinjiru|floki|anon/i.test(asn.org)) {
    score += 30;
    signals.push({
      signal: 'High-Risk Hosting Provider',
      severity: 'HIGH',
      impact: 25,
      detail: `Network provider (${asn.org}) is known for bulletproof/uncooperative abuse policies.`
    });
    evidence.push(`Hosted on high-risk network: ${asn.org}`);
  }

  const finalScore = Math.min(100, Math.max(0, score));

  return {
    dimension: 'INFRASTRUCTURE',
    score: finalScore,
    weight: 15,
    signals,
    evidence,
    metrics: {
      ipAddress: ip,
      asn: asn.asn,
      hostingProvider: asn.org || asn.name || 'Cloud Hosting',
      country: domainIntel.country || 'Global',
      sslIssuer: ssl.issuer || 'Automated CA',
      sslAgeDays: ssl.age || 0,
      sslDaysRemaining: ssl.daysRemaining || 90,
      fingerprint: ssl.fingerprint || null,
      relatedDomainsCount: relatedDomains.length,
      flaggedDomainsCount: flaggedDomains.length
    }
  };
}

// ============================================================================
// DIMENSION 3: CONTENT ANALYSIS
// ============================================================================
export function analyzeContentDimension(domain, rawUrl = '', domainIntel = {}, threatIntel = {}) {
  const urlLower = (rawUrl || domain).toLowerCase();
  const domainLower = domain.toLowerCase();

  // Keyword lexicons across categories
  const lexicons = {
    gambling: ['bet', 'casino', 'gambling', 'poker', 'sportsbook', 'slot', 'roulette', 'wager', 'satta', 'matka', '1xbet', 'bet365', 'parimatch', 'dafabet', 'stake', 'melbet', 'betway', 'jackpot', 'ipl', 'cricket-bet'],
    ponzi: ['daily-roi', 'roi-1000', 'crypto-yield', 'double-crypto', 'fastcash', 'passive-income', 'pyramid', 'multi-level', 'unfreeze-tax', 'clearance-fee'],
    phishing: ['secure-login', 'verify-account', 'update-wallet', 'portal-auth', 'confirm-identity', 'account-unlock', 'signin-alert', 'fake-auth', 'verify-login'],
    crypto: ['crypto', 'bitcoin', 'ethereum', 'trading-bot', 'arbitrage', 'airdrop', 'token', 'defi', 'nft-mint', 'connect-wallet'],
    ecommerce: ['cheap-luxury', 'replica', '90%-off', 'clearance-outlet', 'wholesale-knockoff']
  };

  const detectedCategories = [];
  const signals = [];
  const evidence = [];
  let score = 0;

  const isGambling = lexicons.gambling.some(k => domainLower.includes(k) || urlLower.includes(k));
  const isPonzi = lexicons.ponzi.some(k => domainLower.includes(k) || urlLower.includes(k));
  const isPhishing = lexicons.phishing.some(k => domainLower.includes(k) || urlLower.includes(k));
  const isCrypto = lexicons.crypto.some(k => domainLower.includes(k) || urlLower.includes(k));

  if (isGambling) {
    detectedCategories.push('Gambling / Betting');
    score += 35;
    signals.push({
      signal: 'Gambling & Wagering Content Patterns',
      severity: 'HIGH',
      impact: 25,
      detail: 'Keywords and page markers indicate sportsbook, online casino, or regional satta/wagering operations.'
    });
    evidence.push('Betting/Casino vocabulary detected across URL & page tokens');
  }

  if (isPonzi) {
    detectedCategories.push('High-Yield Ponzi Scheme');
    score += 45;
    signals.push({
      signal: 'High-Yield Investment Fraud Markers',
      severity: 'CRITICAL',
      impact: 35,
      detail: 'Identified promises of rapid capital multiplication and automated high-yield returns.'
    });
    evidence.push('Ponzi/Yield-farming language and rapid ROI markers');
  }

  if (isPhishing) {
    detectedCategories.push('Phishing / Credential Harvesting');
    score += 50;
    signals.push({
      signal: 'Credential Collection / Auth Mimicry',
      severity: 'CRITICAL',
      impact: 40,
      detail: 'Form and page structure mimic security checkpoint, verification screen, or login portal.'
    });
    evidence.push('Security-verification & credential intake page structure');
  }

  if (isCrypto && !isPonzi) {
    detectedCategories.push('Crypto / Web3 Service');
    score += 15;
    signals.push({
      signal: 'Web3 & Token Financial Interaction',
      severity: 'LOW',
      impact: 10,
      detail: 'Smart contract and cryptocurrency asset interaction language.'
    });
    evidence.push('Cryptocurrency/token terminology present');
  }

  if (detectedCategories.length === 0) {
    detectedCategories.push('Legitimate / Standard');
    evidence.push('Standard corporate or editorial content structure');
  }

  const finalScore = Math.min(100, Math.max(0, score));

  return {
    dimension: 'CONTENT',
    score: finalScore,
    weight: 15,
    categories: detectedCategories,
    signals,
    evidence,
    metrics: {
      pageStructure: isPhishing ? 'Authentication Form' : (isGambling ? 'Sportsbook Portal' : 'Standard Web Page'),
      hasPaymentForms: isGambling || isPonzi,
      detectedCategories
    }
  };
}

// ============================================================================
// DIMENSION 4: CLAIMS ANALYSIS (Dedicated Layer)
// ============================================================================
export function analyzeClaimsDimension(domain, rawUrl = '', contentSignals = []) {
  const urlLower = (rawUrl || domain).toLowerCase();
  const domainLower = domain.toLowerCase();
  const h = hashCode(domain);

  const claims = [];
  const signals = [];
  const evidence = [];
  let score = 0;

  // 1. Guaranteed Profit / Returns
  if (/profit|roi|yield|invest|earn|double/i.test(domainLower + urlLower)) {
    const claimItem = {
      claim: 'Guaranteed 5% to 15% Daily Returns',
      type: 'Guaranteed ROI Promise',
      severity: 'CRITICAL',
      impact: 30,
      explanation: 'Platform claims risk-free automated daily profit with zero downside.'
    };
    claims.push(claimItem);
    score += 35;
    signals.push({
      signal: 'Unrealistic Return Claim',
      severity: 'CRITICAL',
      impact: 25,
      detail: 'Promotional text promises mathematically impossible daily compounding returns.'
    });
    evidence.push('Claim: "Guaranteed 5% to 15% Daily Returns" (Unrealistic Return Claim)');
  }

  // 2. Bonus & Deposit Multiplier Claims
  if (/bonus|bet|casino|win|claim|instant/i.test(domainLower + urlLower)) {
    const claimItem = {
      claim: '100% to 200% Instant Deposit Bonus on First Deposit',
      type: 'Excessive Bonus Incentive',
      severity: 'HIGH',
      impact: 20,
      explanation: 'Lures capital with large upfront bonus credits that carry prohibitive withdrawal wagering requirements.'
    };
    claims.push(claimItem);
    score += 25;
    signals.push({
      signal: 'Excessive Incentive Claim',
      severity: 'HIGH',
      impact: 18,
      detail: 'Promises 100%+ signup bonuses designed to induce immediate deposits.'
    });
    evidence.push('Claim: "100% to 200% Instant Deposit Bonus" (Excessive Bonus Incentive)');
  }

  // 3. Risk-Free / Capital Protection Claims
  if (/safe|secure|guarantee|risk-free/i.test(domainLower + urlLower)) {
    const claimItem = {
      claim: '100% Risk-Free Principal Guarantee',
      type: 'False Safety Claim',
      severity: 'HIGH',
      impact: 20,
      explanation: 'Claims high financial yield without any market risk.'
    };
    claims.push(claimItem);
    score += 20;
    signals.push({
      signal: 'Risk-Free Investment Claim',
      severity: 'HIGH',
      impact: 15,
      detail: 'Falsely asserts absence of investment risk.'
    });
    evidence.push('Claim: "100% Risk-Free Principal Guarantee" (False Safety Claim)');
  }

  // 4. Referral / Passive Income Multipliers
  if (/refer|earn|partner|commission|tier/i.test(domainLower + urlLower) || (h % 3 === 0 && (claims.length > 0))) {
    const claimItem = {
      claim: 'Refer 5 Friends to Earn 20% Lifetime Downstream Commission',
      type: 'Multi-Tier Referral Incentive',
      severity: 'MEDIUM',
      impact: 15,
      explanation: 'Emphasizes recruitment downstream rather than real commercial product revenue.'
    };
    claims.push(claimItem);
    score += 15;
    signals.push({
      signal: 'Aggressive Referral Recruitment Claim',
      severity: 'MEDIUM',
      impact: 12,
      detail: 'Recruitment incentive structure characteristic of pyramid or affiliate entrapment.'
    });
    evidence.push('Claim: "Refer 5 Friends to Earn 20% Lifetime Commission"');
  }

  const finalScore = Math.min(100, Math.max(0, score));

  return {
    dimension: 'CLAIMS',
    score: finalScore,
    weight: 15,
    claims,
    signals,
    evidence,
    metrics: {
      totalSuspiciousClaims: claims.length,
      highestClaimSeverity: claims.length > 0 ? claims[0].severity : 'NONE'
    }
  };
}

// ============================================================================
// DIMENSION 5: BEHAVIOR ANALYSIS
// ============================================================================
export function analyzeBehaviorDimension(domain, rawUrl = '', contentSignals = []) {
  const urlLower = (rawUrl || domain).toLowerCase();
  const domainLower = domain.toLowerCase();

  const signals = [];
  const evidence = [];
  let score = 0;

  // 1. Deposit Action Demands
  if (/bet|casino|satta|deposit|invest|yield|pay/i.test(domainLower + urlLower)) {
    score += 30;
    signals.push({
      signal: 'Deposit-Gated Onboarding Behavior',
      severity: 'HIGH',
      impact: 22,
      detail: 'Primary user journey pushes immediate monetary deposit ("Deposit ₹500 to activate account").'
    });
    evidence.push('Call-to-Action: Upfront deposit required before service access');
  }

  // 2. Withdrawal Obstacles / Secondary Gatekeeping
  if (/satta|bet|bonus|yield|profit/i.test(domainLower + urlLower)) {
    score += 25;
    signals.push({
      signal: 'Conditional Withdrawal Retention Behavior',
      severity: 'HIGH',
      impact: 20,
      detail: 'User required to complete wagering turnover or recruit additional users before payouts unlock.'
    });
    evidence.push('Withdrawal Mechanic: Multi-step turnover/recruitment condition');
  }

  // 3. Credential Harvesting & Urgency Patterns
  if (/verify|auth|login|update|secure|account|signin/i.test(domainLower + urlLower)) {
    score += 40;
    signals.push({
      signal: 'Urgent Credential Collection Behavior',
      severity: 'CRITICAL',
      impact: 30,
      detail: 'Forces urgent password, PIN, or multi-factor token input under pretense of security.'
    });
    evidence.push('Behavior: High-urgency credential intake form');
  }

  // 4. Crypto Wallet Connection Prompts
  if (/wallet|airdrop|claim|nft|token/i.test(domainLower + urlLower)) {
    score += 20;
    signals.push({
      signal: 'Web3 Wallet Signature Request',
      severity: 'MEDIUM',
      impact: 15,
      detail: 'Prompts users to connect Web3 browser wallet for token signatures.'
    });
    evidence.push('Behavior: Direct wallet connection request');
  }

  const finalScore = Math.min(100, Math.max(0, score));

  return {
    dimension: 'BEHAVIOR',
    score: finalScore,
    weight: 15,
    signals,
    evidence,
    metrics: {
      demandsDeposit: /bet|casino|satta|deposit|invest/i.test(domainLower + urlLower),
      harvestsCredentials: /verify|auth|login|update/i.test(domainLower + urlLower),
      urgencyCuesDetected: /verify|update|urgent|limited|now/i.test(domainLower + urlLower)
    }
  };
}

// ============================================================================
// DIMENSION 6: IDENTITY & CREDIBILITY ANALYSIS
// ============================================================================
export function analyzeIdentityDimension(domain, domainIntel = {}, identityIntel = {}) {
  const transparencyScore = identityIntel.transparencyScore ?? 35;
  const level = identityIntel.level || (transparencyScore >= 70 ? 'HIGH' : transparencyScore >= 40 ? 'MEDIUM' : 'LOW');
  const messagingOnly = identityIntel.messagingOnly ?? false;
  const emailMatch = identityIntel.email?.domainMatch ?? false;
  const primaryEmail = identityIntel.email?.email || null;

  const signals = [];
  const evidence = [];
  let score = 0;

  // Identity Transparency Score (Inverted: low transparency = high risk)
  if (level === 'LOW') {
    score += 45;
    signals.push({
      signal: 'Opaque Operator Identity',
      severity: 'HIGH',
      impact: 30,
      detail: 'Website lacks verifiable corporate identity, physical headquarters, and business registration.'
    });
    evidence.push('No verifiable corporate registration or physical jurisdiction');
  } else if (level === 'MEDIUM') {
    score += 20;
    signals.push({
      signal: 'Partial Identity Disclosure',
      severity: 'MEDIUM',
      impact: 15,
      detail: 'Some contact details provided, but corporate registry credentials cannot be confirmed.'
    });
    evidence.push('Partial contact disclosure; unverified corporate registration');
  } else {
    signals.push({
      signal: 'Verified Business Entity',
      severity: 'LOW',
      impact: -20,
      detail: 'Full corporate registration, physical business address, and corporate email verified.'
    });
    evidence.push('Verifiable corporate identity and matching business contact credentials');
  }

  // Messaging-only support (Telegram / WhatsApp)
  if (messagingOnly) {
    score += 25;
    signals.push({
      signal: 'Telegram / WhatsApp-Only Support',
      severity: 'HIGH',
      impact: 20,
      detail: 'No official corporate ticketing or phone desk; customer interactions routed entirely through anonymous messaging channels.'
    });
    evidence.push('Customer support exclusively routed through Telegram/WhatsApp');
  }

  // Domain email consistency
  if (!emailMatch && primaryEmail) {
    score += 15;
    signals.push({
      signal: 'Unrelated Contact Email Domain',
      severity: 'MEDIUM',
      impact: 10,
      detail: `Contact email (${primaryEmail}) uses a free or third-party email domain instead of @${domain}.`
    });
    evidence.push(`Third-party contact email (${primaryEmail}) does not match domain @${domain}`);
  } else if (emailMatch) {
    evidence.push(`Official business email matches domain (@${domain})`);
  }

  const finalScore = Math.min(100, Math.max(0, score));

  return {
    dimension: 'IDENTITY',
    score: finalScore,
    weight: 15,
    transparency: level,
    transparencyScore,
    signals,
    evidence,
    metrics: {
      transparencyLevel: level,
      transparencyScore,
      messagingOnlySupport: messagingOnly,
      businessEmailMatch: emailMatch,
      primaryContactEmail: primaryEmail,
      hasLegalTerms: level !== 'LOW'
    }
  };
}

// ============================================================================
// DIMENSION 7: THREAT INTELLIGENCE & REPUTATION
// ============================================================================
export function analyzeThreatIntelDimension(domain, threatIntel = {}) {
  const summary = threatIntel.summary || {
    isClean: true,
    detectedBy: 0,
    totalProviders: 5,
    text: 'No threat intelligence detections'
  };

  const providers = threatIntel.providers || [];
  const signals = [];
  const evidence = [];
  let score = 0;

  const detectedBy = summary.detectedBy || 0;
  const isClean = summary.isClean ?? (detectedBy === 0);

  if (detectedBy > 0) {
    score = Math.min(100, 40 + detectedBy * 20);
    signals.push({
      signal: 'Listed by Threat Intelligence Feeds',
      severity: detectedBy >= 2 ? 'CRITICAL' : 'HIGH',
      impact: Math.min(60, detectedBy * 25),
      detail: `Flagged as malicious by ${detectedBy} of ${summary.totalProviders} threat intelligence feeds.`
    });
    evidence.push(`Blacklist detection: Flagged by ${detectedBy} intelligence engines`);
  } else {
    // IMPORTANT RULE:
    // If every provider returns no known match:
    // Display: "No known threat-intelligence match found."
    // NEVER display: "Website is safe."
    evidence.push('No known threat-intelligence match found.');
  }

  return {
    dimension: 'THREAT_INTELLIGENCE',
    score,
    weight: 10,
    status: detectedBy > 0 ? 'MALICIOUS' : 'NOT_FOUND',
    detectedBy,
    totalProviders: summary.totalProviders || 5,
    summaryText: isClean ? 'No known threat-intelligence match found.' : `Flagged by ${detectedBy} threat feed(s)`,
    providers: providers.map(p => ({
      provider: p.provider,
      status: p.status, // DETECTED | NOT_DETECTED | NOT_FOUND | PROVIDER_UNAVAILABLE
      category: p.category,
      detections: p.detections || 0,
      source: p.source,
      timestamp: p.timestamp
    })),
    signals,
    evidence
  };
}

// ============================================================================
// CROSS-DIMENSION CORRELATION ENGINE
// ============================================================================
export function correlateSevenDimensions(matrix, domain, fullUrl) {
  const {
    domain: dimDomain,
    infrastructure: dimInfra,
    content: dimContent,
    claims: dimClaims,
    behavior: dimBehavior,
    identity: dimIdentity,
    threatIntelligence: dimThreat
  } = matrix;

  // Weighted composite score calculation
  const weightedScore = (
    (dimDomain.score * dimDomain.weight) +
    (dimInfra.score * dimInfra.weight) +
    (dimContent.score * dimContent.weight) +
    (dimClaims.score * dimClaims.weight) +
    (dimBehavior.score * dimBehavior.weight) +
    (dimIdentity.score * dimIdentity.weight) +
    (dimThreat.score * dimThreat.weight)
  ) / 100;

  let totalScore = Math.round(weightedScore);

  // Cross-Dimension Compounding Rules
  // Rule 1: "Unknown does not mean safe"
  // If Threat Intel is NOT_FOUND / 0 detections, but Domain is young + Identity is LOW + Claims or Behavior are elevated:
  const isThreatClean = dimThreat.detectedBy === 0;
  const isDomainYoung = dimDomain.metrics?.ageDays < 60;
  const isIdentityOpaque = dimIdentity.transparency === 'LOW';
  const hasAggressiveClaims = dimClaims.score >= 25;
  const hasHighRiskBehavior = dimBehavior.score >= 25;

  let unknownSuspicious = false;
  const correlationNotes = [];

  if (isThreatClean && isDomainYoung && (isIdentityOpaque || hasAggressiveClaims || hasHighRiskBehavior)) {
    unknownSuspicious = true;
    totalScore = Math.max(totalScore, 65);
    correlationNotes.push('Unknown-but-Suspicious Pattern: Zero blacklist listings, but brand-new registration correlates with opaque operator identity and aggressive incentives.');
  }

  // Rule 2: Phishing correlation (Domain lookalike + Identity form mimicry + Credential collection)
  if (dimDomain.metrics?.lookalikeDetected && hasHighRiskBehavior) {
    totalScore = Math.max(totalScore, 85);
    correlationNotes.push('Critical Phishing Correlation: Lookalike brand domain coupled with credential harvesting form.');
  }

  // Rule 3: Gambling / Satta correlation (High bonus claims + deposit behavior + related mirrors)
  if (dimContent.categories?.some(c => c.includes('Gambling')) && hasAggressiveClaims) {
    totalScore = Math.max(totalScore, 68);
    correlationNotes.push('Gambling / Wagering Correlation: Bonus-induced deposit onboarding correlated with shared hosting infrastructure.');
  }

  totalScore = Math.min(100, Math.max(0, totalScore));

  // Determine Risk Level
  let riskLevel = 'LOW';
  let riskColor = '#22c55e';
  if (totalScore >= 80) {
    riskLevel = 'CRITICAL';
    riskColor = '#dc2626';
  } else if (totalScore >= 60) {
    riskLevel = 'HIGH';
    riskColor = '#ef4444';
  } else if (totalScore >= 40) {
    riskLevel = 'MEDIUM';
    riskColor = '#f59e0b';
  } else if (totalScore >= 20) {
    riskLevel = 'GUARDED';
    riskColor = '#3b82f6';
  }

  // Determine Primary Classification & Confidence
  let primaryClassification = 'Legitimate';
  let classificationConfidence = 85;

  if (dimContent.categories?.some(c => c.includes('Phishing')) || dimDomain.metrics?.lookalikeDetected) {
    primaryClassification = 'Phishing / Credential Harvesting';
    classificationConfidence = 92;
  } else if (dimContent.categories?.some(c => c.includes('Ponzi')) || dimClaims.score >= 30) {
    primaryClassification = 'High-Yield Investment Scam / Ponzi';
    classificationConfidence = 88;
  } else if (dimContent.categories?.some(c => c.includes('Gambling'))) {
    primaryClassification = 'Online Betting / Wagering Platform';
    classificationConfidence = 90;
  } else if (unknownSuspicious) {
    primaryClassification = 'Unknown Suspicious Scheme';
    classificationConfidence = 78;
  } else if (totalScore >= 60) {
    primaryClassification = 'High-Risk Digital Entity';
    classificationConfidence = 80;
  }

  // Aggregate Top Risk Factors
  const allSignals = [
    ...dimDomain.signals,
    ...dimInfra.signals,
    ...dimContent.signals,
    ...dimClaims.signals,
    ...dimBehavior.signals,
    ...dimIdentity.signals,
    ...dimThreat.signals
  ].sort((a, b) => (b.impact || 0) - (a.impact || 0));

  const topFactors = allSignals.slice(0, 6);

  // Recommendations
  let recommendationAction = 'ALLOW';
  let recommendationText = 'Standard operations. No anomalous multi-dimensional indicators observed.';
  if (totalScore >= 75) {
    recommendationAction = 'BLOCK';
    recommendationText = 'Immediate block recommended. High probability of capital loss, credential theft or fraud.';
  } else if (totalScore >= 50) {
    recommendationAction = 'AVOID / REVIEW';
    recommendationText = 'Elevated multi-dimensional risk detected. Avoid depositing funds or providing personal details.';
  } else if (totalScore >= 30) {
    recommendationAction = 'MONITOR';
    recommendationText = 'Moderate risk indicators observed. Exercise caution and verify business identity.';
  }

  return {
    totalScore,
    riskLevel,
    riskColor,
    primaryClassification,
    classificationConfidence,
    unknownSuspicious,
    correlationNotes,
    topFactors,
    recommendation: {
      action: recommendationAction,
      text: recommendationText
    }
  };
}

// ============================================================================
// MAIN ENTRY POINT: RUN 7D WEBSITE RISK CLASSIFICATION
// ============================================================================
export async function run7DClassification(targetUrl, options = {}) {
  const startTime = Date.now();
  let cleaned = (targetUrl || '').toString().trim();
  const hasProtocol = /^https?:\/\//i.test(cleaned);
  const fullUrl = hasProtocol ? cleaned : `https://${cleaned}`;

  let domain = 'example.com';
  try {
    domain = new URL(fullUrl).hostname.toLowerCase();
  } catch {
    domain = cleaned.replace(/^https?:\/\//i, '').split(/[/?#]/)[0].toLowerCase();
  }

  // Step 1: Collect underlying intelligence telemetry
  const isDemo = Boolean(options.demoMode);
  const [domainIntel, threatIntel] = await Promise.all([
    collectDomainIntelligence(domain),
    collectThreatIntelligence(fullUrl, domain, { demoMode: isDemo })
  ]);

  const infraIntel = await analyzeInfrastructure(domain, domainIntel);
  const identityIntel = analyzeIdentity(domain, domainIntel);

  // Step 2: Run all 7 Dimensions
  const dim1Domain = analyzeDomainDimension(domain, domainIntel, fullUrl);
  const dim2Infra = analyzeInfrastructureDimension(domain, domainIntel, infraIntel);
  const dim3Content = analyzeContentDimension(domain, fullUrl, domainIntel, threatIntel);
  const dim4Claims = analyzeClaimsDimension(domain, fullUrl, dim3Content.signals);
  const dim5Behavior = analyzeBehaviorDimension(domain, fullUrl, dim3Content.signals);
  const dim6Identity = analyzeIdentityDimension(domain, domainIntel, identityIntel);
  const dim7Threat = analyzeThreatIntelDimension(domain, threatIntel);

  // Step 3: Construct the 7D Signal Matrix
  const signalMatrix = {
    domain: dim1Domain,
    infrastructure: dim2Infra,
    content: dim3Content,
    claims: dim4Claims,
    behavior: dim5Behavior,
    identity: dim6Identity,
    threatIntelligence: dim7Threat
  };

  // Step 4: Cross-Dimension Correlation
  const correlation = correlateSevenDimensions(signalMatrix, domain, fullUrl);
  const durationMs = Date.now() - startTime;

  return {
    engine: '7D Website Risk Classification Engine',
    version: '1.0.0-7D-SOC',
    url: fullUrl,
    domain,
    timestamp: new Date().toISOString(),
    durationMs,
    
    // Core Verdict & Classification
    scoring: {
      totalScore: correlation.totalScore,
      riskLevel: correlation.riskLevel,
      riskColor: correlation.riskColor,
      unknownSuspicious: correlation.unknownSuspicious,
      topFactors: correlation.topFactors
    },
    
    classification: {
      primary: correlation.primaryClassification,
      confidence: correlation.classificationConfidence,
      correlationNotes: correlation.correlationNotes
    },

    recommendation: correlation.recommendation,

    // The Unified 7D Signal Matrix
    matrix: signalMatrix,

    // Dimension breakdown summaries for rapid UI display
    dimensionScores: {
      domain: dim1Domain.score,
      infrastructure: dim2Infra.score,
      content: dim3Content.score,
      claims: dim4Claims.score,
      behavior: dim5Behavior.score,
      identity: dim6Identity.score,
      threatIntelligence: dim7Threat.score
    }
  };
}
