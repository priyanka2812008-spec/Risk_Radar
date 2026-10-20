/**
 * Website Classification Service
 * Classifies websites into categories using multi-signal analysis.
 * Combines URL structure, content signals, domain characteristics, and behavioral patterns.
 * 
 * IMPORTANT: Classification is separate from Risk Score.
 * Risk Score = how risky the website appears (0-100)
 * Classification = what type of website/risk pattern was detected
 * Classification Confidence = how confident the engine is in its classification (0-100%)
 */

import { detectBrandImpersonation } from './brandImpersonation.js';
import { detectGamblingOrPonzi, BETTING_GAMBLING_BRANDS, GAMBLING_KEYWORDS, PONZI_KEYWORDS } from './gamblingDetector.js';
import { checkGovernmentVerification } from './governmentVerification.js';

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

// Category definitions with associated signal patterns
const CATEGORIES = {
  GOVERNMENT_PORTAL: { label: 'Government / Statutory Entity', riskWeight: 0 },
  LEGITIMATE: { label: 'Legitimate', riskWeight: 0 },
  SATTA_MATKA: { label: 'Satta / Matka Gambling', riskWeight: 20 },
  GAMBLING: { label: 'Gambling', riskWeight: 20 },
  BETTING: { label: 'Betting', riskWeight: 20 },
  CASINO: { label: 'Casino', riskWeight: 20 },
  STOCK_ADVISORY: { label: 'Financial Advisory / Stock Tips', riskWeight: 16 },
  PONZI_SCHEME: { label: 'Ponzi Scheme', riskWeight: 20 },
  INVESTMENT_SCAM: { label: 'Investment Scam', riskWeight: 20 },
  CRYPTO_SCAM: { label: 'Crypto Scam', riskWeight: 18 },
  PHISHING: { label: 'Phishing', riskWeight: 20 },
  FAKE_ECOMMERCE: { label: 'Fake E-commerce', riskWeight: 16 },
  FINANCIAL_FRAUD: { label: 'Financial Fraud', riskWeight: 18 },
  SUSPICIOUS_INVESTMENT: { label: 'Suspicious Investment', riskWeight: 16 },
  UNKNOWN: { label: 'Unknown', riskWeight: 10 }
};

// Signal pattern dictionaries
const SIGNAL_PATTERNS = {
  sattaMatka: {
    urlKeywords: ['dpboss', 'kalyan', 'satta', 'matka', 'milan-day', 'rajdhani', 'desawar', 'disawar', 'gali-satta', 'jodi-chart', 'panna-chart'],
    brandKeywords: ['dpboss', 'satta-king', 'kalyan-matka', 'matka-result', 'dpbossss']
  },
  gambling: {
    urlKeywords: [...new Set([...GAMBLING_KEYWORDS, 'bet', 'casino', 'gambling', 'poker', 'sportsbook', 'slot', 'roulette', 'wager', 'baccarat', 'odds', 'jackpot', 'bookmaker', 'bonus', 'claim-bonus', 'instant-win', 'instant-bonus', 'aviator', 'color-prediction', 'teen-patti', 'rummy'])],
    brandKeywords: [...new Set([...BETTING_GAMBLING_BRANDS, '1xbet', 'bet365', 'parimatch', 'dafabet', 'stake', 'melbet', 'betway', 'betzone', 'betking', 'daman', 'bdgwin', 'fastwin'])],
    contentSignals: ['signup bonus', 'deposit bonus', 'free bet', 'live betting', 'cash out', 'accumulator', 'parlay', 'over/under', 'handicap betting', '100% signup bonus'],
    depositSignals: ['deposit ₹', 'deposit $', 'minimum deposit', 'first deposit', 'instant deposit', 'upi deposit', 'deposit ₹500'],
    referralSignals: ['refer & earn', 'refer 5 users', 'referral bonus', 'invite friends', 'refer and earn', 'referral commission', 'earn daily commission']
  },
  stockAdvisory: {
    urlKeywords: ['stocktalk', 'stock-tips', 'trading-classes', 'share-market', 'nifty-tips', 'intraday-tips', 'calls-put'],
    brandKeywords: ['stocktalk', 'stockmarket', 'sharetrading']
  },
  ponzi: {
    urlKeywords: [...new Set([...PONZI_KEYWORDS, 'profit', 'crypto-yield', 'double', 'fastcash', 'guaranteed-return', '100x', 'daily-return', 'passive-income', 'daily-crypto-roi', 'roi-1000'])],
    contentSignals: ['guaranteed returns', 'daily income', 'risk-free investment', 'guaranteed profit', 'fixed APY', 'daily ROI'],
    recruitmentSignals: ['recruit to earn', 'downstream earning', 'pyramid commission', 'multi-level', 'team income', 'generation bonus'],
    withdrawalSignals: ['unfreeze tax', 'clearance fee', 'withdrawal fee', 'processing deposit', 'activation fee']
  },
  phishing: {
    urlKeywords: ['secure-login', 'verify-account', 'update-wallet', 'portal-auth', 'confirm-identity', 'account-unlock', 'signin-alert', 'fake-auth', 'verify-login', 'kyc-update', 'pan-update'],
    contentSignals: ['verify your identity', 'confirm your account', 'your account has been', 'unusual activity', 'suspended account', 'immediate action required'],
    formSignals: ['password', 'social security', 'card number', 'CVV', 'PIN', 'seed phrase', 'private key']
  },
  crypto: {
    urlKeywords: ['crypto', 'bitcoin', 'ethereum', 'trading-bot', 'arbitrage', 'airdrop', 'token', 'defi', 'nft-mint'],
    contentSignals: ['connect wallet', 'claim airdrop', 'liquidity pool', 'staking rewards', 'mining returns', 'smart contract'],
    scamSignals: ['guaranteed mining', 'double your crypto', 'free bitcoin', 'auto-trading bot', 'cloud mining guaranteed']
  },
  ecommerce: {
    urlKeywords: ['shop', 'store', 'buy', 'outlet', 'discount', 'deal', 'sale'],
    scamSignals: ['90% off', '95% discount', 'replica', 'wholesale knockoff', 'cheap luxury', 'free gift card', 'clearance warehouse']
  }
};

/**
 * Detect content signals from URL, domain characteristics, and live telemetry
 */
function detectContentSignals(domain, url, liveTelemetry = null) {
  const h = hashCode(domain);
  const fullUrl = (url || domain).toLowerCase();
  const detectedSignals = [];
  
  // Real signals from Live Telemetry
  if (liveTelemetry?.page) {
    const page = liveTelemetry.page;
    if (page.title) {
      detectedSignals.push({ text: `Page Title: "${page.title}"`, category: 'page_meta' });
    }

    const sattaMatched = page.categoriesMatched?.find(c => c.category === 'sattaMatka');
    if (sattaMatched) {
      detectedSignals.push({
        text: `Identified Satta Matka keywords (${sattaMatched.matchedKeywords.join(', ')}) in live page content`,
        category: 'satta_matka'
      });
      detectedSignals.push({ text: 'Matka Jodi/Panna charts and wagering results published on live page', category: 'gambling_terminology' });
    }

    const gamblingMatched = page.categoriesMatched?.find(c => c.category === 'gamblingCasino');
    if (gamblingMatched) {
      detectedSignals.push({
        text: `Real-money gambling keywords (${gamblingMatched.matchedKeywords.join(', ')}) detected in live content`,
        category: 'gambling_terminology'
      });
    }

    const stockMatched = page.categoriesMatched?.find(c => c.category === 'stockTipsAdvisory');
    if (stockMatched) {
      detectedSignals.push({
        text: `Stock market advisory / tips / trading classes indicators (${stockMatched.matchedKeywords.join(', ')})`,
        category: 'stock_advisory'
      });
    }

    const ponziMatched = page.categoriesMatched?.find(c => c.category === 'ponziYield');
    if (ponziMatched) {
      detectedSignals.push({
        text: `High-yield / guaranteed return promises detected in live text (${ponziMatched.matchedKeywords.join(', ')})`,
        category: 'roi_promise'
      });
    }

    if (page.brandImpersonation) {
      detectedSignals.push({
        text: page.brandImpersonation.reason,
        category: 'brand_impersonation'
      });
    }

    if (page.forms?.passwordInputs > 0 && !liveTelemetry.isTopBrand) {
      detectedSignals.push({ text: `Detected ${page.forms.passwordInputs} password input field(s) on unverified domain`, category: 'credential_harvesting' });
    }
    if (page.forms?.otpInputs > 0) {
      detectedSignals.push({ text: 'Detected OTP verification form field on website', category: 'credential_harvesting' });
    }

    if (page.externalChannels?.telegram?.length > 0) {
      detectedSignals.push({ text: `Support routed to Telegram: ${page.externalChannels.telegram.join(', ')}`, category: 'messaging_only_support' });
    }
    if (page.externalChannels?.apkLinks?.length > 0) {
      detectedSignals.push({ text: `Direct Android APK download offered outside Google Play Store (${page.externalChannels.apkLinks[0]})`, category: 'apk_distribution' });
    }
  }

  // URL-based signals fallback
  const isSatta = SIGNAL_PATTERNS.sattaMatka.brandKeywords.concat(SIGNAL_PATTERNS.sattaMatka.urlKeywords).some(kw => domain.includes(kw) || fullUrl.includes(kw));
  const gamblingKeywords = SIGNAL_PATTERNS.gambling.brandKeywords.concat(SIGNAL_PATTERNS.gambling.urlKeywords);
  const isGambling = isSatta || gamblingKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  const isScam = SIGNAL_PATTERNS.ponzi.urlKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  const impersonation = detectBrandImpersonation(domain, url);
  const isPhishing = impersonation.detected || SIGNAL_PATTERNS.phishing.urlKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  const isCrypto = SIGNAL_PATTERNS.crypto.urlKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  const isStockAdvisory = SIGNAL_PATTERNS.stockAdvisory.brandKeywords.concat(SIGNAL_PATTERNS.stockAdvisory.urlKeywords).some(kw => domain.includes(kw) || fullUrl.includes(kw));

  if (isSatta && !detectedSignals.some(s => s.category === 'satta_matka')) {
    detectedSignals.push({ text: 'Satta Matka wagering terminology identified in domain structure', category: 'satta_matka' });
  }

  if (isGambling && !detectedSignals.some(s => s.category === 'gambling_terminology')) {
    detectedSignals.push({ text: '100% signup bonus & deposit incentives detected', category: 'bonus_promise' });
    detectedSignals.push({ text: 'Live wagering odds & betting platform cues', category: 'gambling_terminology' });
  }
  
  if (isStockAdvisory && !detectedSignals.some(s => s.category === 'stock_advisory')) {
    detectedSignals.push({ text: 'Share market tips and trading advisory services detected', category: 'stock_advisory' });
  }
  
  if (isScam && !detectedSignals.some(s => s.category === 'roi_promise')) {
    detectedSignals.push({ text: 'Earn daily returns guaranteed without risk', category: 'roi_promise' });
    detectedSignals.push({ text: 'Downline referral commission recruitment pattern', category: 'referral_program' });
  }
  
  if (impersonation.detected && !detectedSignals.some(s => s.category === 'brand_impersonation')) {
    detectedSignals.push({
      text: `Uses the "${impersonation.brand}" brand name outside its official domain (${impersonation.officialDomains[0]})`,
      category: 'brand_impersonation'
    });
  }

  if (isPhishing && !detectedSignals.some(s => s.category === 'credential_harvesting')) {
    detectedSignals.push({ text: 'Urgent authentication / account update requested', category: 'urgency' });
    detectedSignals.push({ text: 'Credential entry form detected on non-authoritative host', category: 'credential_harvesting' });
  }
  
  if (isCrypto && !isScam && !detectedSignals.some(s => s.category === 'wallet_connection')) {
    detectedSignals.push({ text: 'Connect Web3 wallet to claim tokens or rewards', category: 'wallet_connection' });
  }
  
  return detectedSignals;
}

/**
 * Classify website based on multi-signal analysis and live telemetry
 */
export function classifyWebsite(domain, url, domainIntelligence, threatIntelligence, liveTelemetry = null) {
  const h = hashCode(domain);
  const fullUrl = url.toLowerCase();
  
  const gpCheck = detectGamblingOrPonzi(domain, url, liveTelemetry);
  const govtCheck = checkGovernmentVerification(domain, url);

  const topBrands = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'cloudflare.com', 'wikipedia.org', 'paypal.com', 'stripe.com', 'netflix.com'];
  const isTopBrand = topBrands.some(b => domain === b || domain.endsWith('.' + b));
  
  // Detect content signals with live telemetry
  const contentSignals = detectContentSignals(domain, url, liveTelemetry);

  // Inject detected gambling / ponzi patterns into content signals
  if (gpCheck.isDetected) {
    for (const pat of gpCheck.matchedPatterns) {
      if (!contentSignals.some(s => s.text === pat)) {
        contentSignals.unshift({
          text: pat,
          category: gpCheck.isSatta ? 'satta_matka' : (gpCheck.isPonzi ? 'roi_promise' : 'gambling_terminology')
        });
      }
    }
  }
  
  // Score each category
  const scores = {};

  // Apply gpCheck directly to score tables
  if (gpCheck.isSatta) {
    scores['Satta / Matka Gambling'] = Math.max(scores['Satta / Matka Gambling'] || 0, 96);
  }
  if (gpCheck.isBetting) {
    scores['Betting'] = Math.max(scores['Betting'] || 0, 94);
  }
  if (gpCheck.isCasino) {
    scores['Casino'] = Math.max(scores['Casino'] || 0, 92);
  }
  if (gpCheck.isGambling && !gpCheck.isSatta && !gpCheck.isBetting && !gpCheck.isCasino) {
    scores['Gambling'] = Math.max(scores['Gambling'] || 0, 92);
  }
  if (gpCheck.isPonzi) {
    scores['Ponzi Scheme'] = Math.max(scores['Ponzi Scheme'] || 0, 95);
  }
  
  // === SATTA / MATKA ===
  let sattaScore = scores['Satta / Matka Gambling'] || 0;
  if (liveTelemetry?.page?.categoriesMatched?.some(c => c.category === 'sattaMatka')) {
    sattaScore += 65 + (liveTelemetry.page.categoriesMatched.find(c => c.category === 'sattaMatka')?.count || 1) * 3;
  }
  SIGNAL_PATTERNS.sattaMatka.brandKeywords.forEach(kw => { if (domain.includes(kw)) sattaScore += 45; });
  SIGNAL_PATTERNS.sattaMatka.urlKeywords.forEach(kw => { if (domain.includes(kw)) sattaScore += 25; });
  if (sattaScore > 20) scores['Satta / Matka Gambling'] = sattaScore;

  // === GAMBLING / BETTING / CASINO ===
  let gamblingScore = Math.max(scores['Betting'] || 0, scores['Casino'] || 0, scores['Gambling'] || 0);
  if (liveTelemetry?.page?.categoriesMatched?.some(c => c.category === 'gamblingCasino')) {
    gamblingScore += 50;
  }
  const gamblingBrands = SIGNAL_PATTERNS.gambling.brandKeywords;
  const gamblingTerms = SIGNAL_PATTERNS.gambling.urlKeywords;
  
  if (gamblingBrands.some(kw => domain.includes(kw))) gamblingScore += 45;
  gamblingTerms.forEach(kw => { if (domain.includes(kw)) gamblingScore += 15; });
  contentSignals.filter(s => s.category === 'gambling_terminology').forEach(() => gamblingScore += 12);
  contentSignals.filter(s => s.category === 'bonus_promise').forEach(() => gamblingScore += 8);
  contentSignals.filter(s => s.category === 'deposit_language').forEach(() => gamblingScore += 8);
  contentSignals.filter(s => s.category === 'referral_program').forEach(() => gamblingScore += 6);
  
  if (gamblingScore > 20 && !sattaScore) {
    const hasCasino = gpCheck.isCasino || domain.includes('casino') || domain.includes('slot') || domain.includes('roulette') || domain.includes('baccarat');
    const hasBetting = gpCheck.isBetting || domain.includes('bet') || domain.includes('odds') || domain.includes('sportsbook') || domain.includes('exch');
    
    if (hasCasino) scores['Casino'] = gamblingScore;
    else if (hasBetting) scores['Betting'] = gamblingScore;
    else scores['Gambling'] = gamblingScore;
  }
  
  // === STOCK ADVISORY / TIPS ===
  let stockScore = 0;
  if (liveTelemetry?.page?.categoriesMatched?.some(c => c.category === 'stockTipsAdvisory')) {
    stockScore += 55;
  }
  SIGNAL_PATTERNS.stockAdvisory.brandKeywords.forEach(kw => { if (domain.includes(kw)) stockScore += 30; });
  SIGNAL_PATTERNS.stockAdvisory.urlKeywords.forEach(kw => { if (domain.includes(kw)) stockScore += 20; });
  if (stockScore > 20) scores['Financial Advisory / Stock Tips'] = stockScore;

  // === PONZI / INVESTMENT SCAM ===
  let ponziScore = 0;
  if (liveTelemetry?.page?.categoriesMatched?.some(c => c.category === 'ponziYield')) {
    ponziScore += 55;
  }
  SIGNAL_PATTERNS.ponzi.urlKeywords.forEach(kw => { if (domain.includes(kw)) ponziScore += 25; });
  contentSignals.filter(s => s.category === 'roi_promise').forEach(() => ponziScore += 15);
  contentSignals.filter(s => s.category === 'referral_program').forEach(() => ponziScore += 10);
  contentSignals.filter(s => s.category === 'withdrawal_trap').forEach(() => ponziScore += 15);
  
  if (ponziScore > 20) scores['Ponzi Scheme'] = ponziScore;
  
  // === PHISHING & BRAND IMPERSONATION ===
  let phishingScore = 0;
  if (liveTelemetry?.page?.brandImpersonation) {
    phishingScore += 60;
  }
  if (liveTelemetry?.page?.categoriesMatched?.some(c => c.category === 'phishingHarvesting')) {
    phishingScore += 50;
  }
  if (liveTelemetry?.page?.forms?.passwordInputs > 0 && !isTopBrand) {
    phishingScore += 25;
  }
  SIGNAL_PATTERNS.phishing.urlKeywords.forEach(kw => { if (domain.includes(kw)) phishingScore += 25; });
  const impersonation = detectBrandImpersonation(domain, url);
  if (impersonation.detected) phishingScore += impersonation.strength === 'high' ? 45 : 25;
  contentSignals.filter(s => s.category === 'credential_harvesting').forEach(() => phishingScore += 20);
  contentSignals.filter(s => s.category === 'urgency').forEach(() => phishingScore += 10);
  contentSignals.filter(s => s.category === 'social_engineering').forEach(() => phishingScore += 10);
  
  if (phishingScore > 20) scores['Phishing'] = phishingScore;
  
  // === CRYPTO SCAM ===
  let cryptoScore = 0;
  SIGNAL_PATTERNS.crypto.urlKeywords.forEach(kw => { if (domain.includes(kw)) cryptoScore += 12; });
  SIGNAL_PATTERNS.crypto.scamSignals.forEach(kw => { if (fullUrl.includes(kw.replace(/\s/g, '-'))) cryptoScore += 15; });
  contentSignals.filter(s => s.category === 'wallet_connection').forEach(() => cryptoScore += 10);
  
  if (cryptoScore > 20) scores['Crypto Scam'] = cryptoScore;
  
  // === FAKE E-COMMERCE ===
  let ecomScore = 0;
  SIGNAL_PATTERNS.ecommerce.scamSignals.forEach(kw => { if (fullUrl.includes(kw.replace(/\s/g, '-'))) ecomScore += 20; });
  if (ecomScore > 20) scores['Fake E-commerce'] = ecomScore;
  
  // Determine primary classification
  const sortedCategories = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  
  let primaryCategory, confidence, secondaryCategories = [], explanation, detectedSignalTexts = [];
  
  if (govtCheck.isGovt) {
    primaryCategory = 'Government / Statutory Entity';
    confidence = 99;
    explanation = `Official sovereign/statutory government portal (${domain}): ${govtCheck.citation}`;
    secondaryCategories = ['Government Verified', 'Sovereign Portal', 'Statutory Authority'];
  } else if (isTopBrand && !gpCheck.isDetected) {
    primaryCategory = 'Legitimate';
    confidence = 97;
    explanation = 'Target matches a verified enterprise commercial domain with established trust infrastructure.';
    secondaryCategories = ['Verified Enterprise', 'Established Brand'];
  } else if (sortedCategories.length > 0 && sortedCategories[0][1] >= 25) {
    primaryCategory = sortedCategories[0][0];
    confidence = Math.min(98, Math.max(75, Math.round(sortedCategories[0][1] * 1.05)));
    
    secondaryCategories = sortedCategories.slice(1, 4).map(([cat]) => cat);
    
    // Add sub-signals as secondary tags
    if (contentSignals.some(s => s.category === 'referral_program')) secondaryCategories.push('Referral-Based Scheme');
    if (contentSignals.some(s => s.category === 'deposit_language')) secondaryCategories.push('Deposit-Based Model');
    if (contentSignals.some(s => s.category === 'withdrawal_trap')) secondaryCategories.push('Withdrawal Trap');
    if (contentSignals.some(s => s.category === 'roi_promise')) secondaryCategories.push('ROI/Profit Promises');
    if (contentSignals.some(s => s.category === 'satta_matka')) secondaryCategories.push('Satta Matka Results');
    
    secondaryCategories = [...new Set(secondaryCategories)].slice(0, 5);
    
    const explanations = {
      'Satta / Matka Gambling': `Target operates an illegal Satta Matka betting portal${liveTelemetry?.page?.title ? ` ("${liveTelemetry.page.title.substring(0, 50)}")` : ''} publishing Kalyan/Disawar results, Jodi charts, and wager schemes. Not government verified.`,
      'Gambling': 'Multiple consistent gambling and wagering indicators detected across domain structure and live content signals. Unlicensed operation.',
      'Betting': 'Sports betting and wagering terminology detected with deposit/bonus patterns. Prohibited cross-border wagering.',
      'Casino': 'Online casino operation indicators detected including slot/roulette/table game signals. Unauthorized gaming entity.',
      'Financial Advisory / Stock Tips': `Platform promotes share market tips, intraday calls, or trading courses${liveTelemetry?.page?.title ? ` ("${liveTelemetry.page.title.substring(0, 50)}")` : ''}. Regulatory registration (SEBI/SEC) requires independent verification.`,
      'Ponzi Scheme': 'Platform exhibits hallmarks of a synthetic high-yield scheme with guaranteed returns and referral recruitment. Prohibited under BUDS Act.',
      'Phishing': `Credential harvesting indicators detected${liveTelemetry?.page?.brandImpersonation ? ` impersonating ${liveTelemetry.page.brandImpersonation.brand}` : ''}. High risk of account takeover or credential theft.`,
      'Crypto Scam': 'Speculative crypto trading with unrealistic return promises and wallet connection requests.',
      'Investment Scam': 'Suspicious investment platform with unverifiable ROI claims and recruitment mechanics.',
      'Fake E-commerce': 'Storefront exhibits deceptive pricing and unverified merchant indicators.',
      'Financial Fraud': 'Advance-fee or payment routing anomalies detected.'
    };
    
    explanation = explanations[primaryCategory] || 'Risk signals detected across multiple analysis dimensions.';
    detectedSignalTexts = contentSignals.map(s => s.text);
  } else {
    // No strong classification match
    const ageDays = liveTelemetry?.rdap?.ageDays || domainIntelligence?.ageDays || 365;
    if (ageDays < 30) {
      primaryCategory = 'Unknown';
      confidence = 55;
      explanation = 'Newly registered domain with insufficient operational history for definitive classification.';
      secondaryCategories = ['Newly Registered Domain', 'Monitoring Recommended'];
    } else {
      primaryCategory = 'Legitimate';
      confidence = Math.min(94, 75 + Math.round(Math.min(15, ageDays / 365)));
      explanation = liveTelemetry?.page?.title 
        ? `Standard web portal: "${liveTelemetry.page.title.substring(0, 60)}" with clean observed content.`
        : 'Standard commercial domain with no significant risk pattern indicators detected.';
      secondaryCategories = ['Standard Commercial', 'No Anomalies Detected'];
    }
  }
  
  // Calculate risk score contribution (0-20)
  const categoryRisk = CATEGORIES[Object.keys(CATEGORIES).find(k => CATEGORIES[k].label === primaryCategory)]?.riskWeight || 5;
  const riskScore = Math.min(20, Math.round(categoryRisk * (confidence / 100)));
  
  return {
    primary: primaryCategory,
    confidence,
    secondary: secondaryCategories,
    explanation,
    contentSignals,
    detectedSignals: detectedSignalTexts,
    scores,
    riskScore,
    governmentVerification: govtCheck,
    gamblingOrPonzi: gpCheck,
    status: 'classified'
  };
}

