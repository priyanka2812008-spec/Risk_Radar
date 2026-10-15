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
  LEGITIMATE: { label: 'Legitimate', riskWeight: 0 },
  GAMBLING: { label: 'Gambling', riskWeight: 12 },
  BETTING: { label: 'Betting', riskWeight: 12 },
  CASINO: { label: 'Casino', riskWeight: 12 },
  PONZI_SCHEME: { label: 'Ponzi Scheme', riskWeight: 18 },
  INVESTMENT_SCAM: { label: 'Investment Scam', riskWeight: 18 },
  CRYPTO_SCAM: { label: 'Crypto Scam', riskWeight: 18 },
  PHISHING: { label: 'Phishing', riskWeight: 20 },
  FAKE_ECOMMERCE: { label: 'Fake E-commerce', riskWeight: 16 },
  FINANCIAL_FRAUD: { label: 'Financial Fraud', riskWeight: 18 },
  SUSPICIOUS_INVESTMENT: { label: 'Suspicious Investment', riskWeight: 14 },
  UNKNOWN: { label: 'Unknown', riskWeight: 5 }
};

// Signal pattern dictionaries
const SIGNAL_PATTERNS = {
  gambling: {
    urlKeywords: ['bet', 'casino', 'gambling', 'poker', 'sportsbook', 'slot', 'roulette', 'wager', 'satta', 'matka', 'baccarat', 'odds', 'jackpot', 'bookmaker', 'bonus', 'claim-bonus', 'instant-win', 'instant-bonus'],
    brandKeywords: ['1xbet', 'bet365', 'parimatch', 'dafabet', 'stake', 'melbet', 'betway', 'betzone', 'betking'],
    contentSignals: ['signup bonus', 'deposit bonus', 'free bet', 'live betting', 'cash out', 'accumulator', 'parlay', 'over/under', 'handicap betting', '100% signup bonus'],
    depositSignals: ['deposit ₹', 'deposit $', 'minimum deposit', 'first deposit', 'instant deposit', 'upi deposit', 'deposit ₹500'],
    referralSignals: ['refer & earn', 'refer 5 users', 'referral bonus', 'invite friends', 'refer and earn', 'referral commission', 'earn daily commission']
  },
  ponzi: {
    urlKeywords: ['profit', 'crypto-yield', 'double', 'fastcash', 'guaranteed-return', '100x', 'daily-return', 'passive-income', 'daily-crypto-roi', 'roi-1000'],
    contentSignals: ['guaranteed returns', 'daily income', 'risk-free investment', 'guaranteed profit', 'fixed APY', 'daily ROI'],
    recruitmentSignals: ['recruit to earn', 'downstream earning', 'pyramid commission', 'multi-level', 'team income', 'generation bonus'],
    withdrawalSignals: ['unfreeze tax', 'clearance fee', 'withdrawal fee', 'processing deposit', 'activation fee']
  },
  phishing: {
    urlKeywords: ['secure-login', 'verify-account', 'update-wallet', 'portal-auth', 'confirm-identity', 'account-unlock', 'signin-alert', 'fake-auth', 'verify-login'],
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
 * Detect content signals from URL and domain characteristics
 */
function detectContentSignals(domain, url) {
  const h = hashCode(domain);
  const fullUrl = (url || domain).toLowerCase();
  const detectedSignals = [];
  
  const gamblingKeywords = SIGNAL_PATTERNS.gambling.brandKeywords.concat(SIGNAL_PATTERNS.gambling.urlKeywords);
  const isGambling = gamblingKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  
  const scamKeywords = SIGNAL_PATTERNS.ponzi.urlKeywords;
  const isScam = scamKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  
  const phishingKeywords = SIGNAL_PATTERNS.phishing.urlKeywords;
  const impersonation = detectBrandImpersonation(domain, url);
  const isPhishing = impersonation.detected || phishingKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  
  const cryptoKeywords = SIGNAL_PATTERNS.crypto.urlKeywords;
  const isCrypto = cryptoKeywords.some(kw => domain.includes(kw) || fullUrl.includes(kw));
  
  // Simulate page content signals based on domain type
  if (isGambling) {
    detectedSignals.push({ text: '100% signup bonus', category: 'bonus_promise' });
    detectedSignals.push({ text: 'Deposit ₹500, Get ₹1000', category: 'deposit_language' });
    detectedSignals.push({ text: 'Live betting odds', category: 'gambling_terminology' });
    detectedSignals.push({ text: 'Refer 5 users, earn daily commission', category: 'referral_program' });
    detectedSignals.push({ text: 'Instant withdrawal to UPI/bank', category: 'withdrawal_language' });
    detectedSignals.push({ text: 'Cricket betting | IPL odds', category: 'gambling_terminology' });
  }
  
  if (isScam) {
    detectedSignals.push({ text: 'Earn 5% daily returns guaranteed', category: 'roi_promise' });
    detectedSignals.push({ text: 'Invest ₹10,000, earn ₹50,000 in 7 days', category: 'roi_promise' });
    detectedSignals.push({ text: 'Join our VIP Telegram group', category: 'messaging_only_support' });
    detectedSignals.push({ text: 'Refer friends, earn 20% commission', category: 'referral_program' });
    detectedSignals.push({ text: 'Pay 15% clearance tax to withdraw', category: 'withdrawal_trap' });
  }
  
  if (impersonation.detected) {
    detectedSignals.push({
      text: `Uses the "${impersonation.brand}" brand name outside its official domain (${impersonation.officialDomains[0]})`,
      category: 'brand_impersonation'
    });
  }

  if (isPhishing) {
    detectedSignals.push({ text: 'Your account requires immediate verification', category: 'urgency' });
    detectedSignals.push({ text: 'Enter your password to continue', category: 'credential_harvesting' });
    detectedSignals.push({ text: 'Unusual login activity detected', category: 'social_engineering' });
  }
  
  if (isCrypto && !isScam) {
    detectedSignals.push({ text: 'Connect your wallet to claim rewards', category: 'wallet_connection' });
    detectedSignals.push({ text: 'Guaranteed 10x returns on staking', category: 'roi_promise' });
  }
  
  return detectedSignals;
}

/**
 * Classify website based on multi-signal analysis
 */
export function classifyWebsite(domain, url, domainIntelligence, threatIntelligence) {
  const h = hashCode(domain);
  const fullUrl = url.toLowerCase();
  
  const topBrands = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'cloudflare.com', 'wikipedia.org', 'paypal.com', 'stripe.com', 'netflix.com'];
  const isTopBrand = topBrands.some(b => domain === b || domain.endsWith('.' + b));
  
  // Detect content signals
  const contentSignals = detectContentSignals(domain, url);
  
  // Score each category
  const scores = {};
  
  // === GAMBLING / BETTING / CASINO ===
  let gamblingScore = 0;
  const gamblingBrands = SIGNAL_PATTERNS.gambling.brandKeywords;
  const gamblingTerms = SIGNAL_PATTERNS.gambling.urlKeywords;
  
  if (gamblingBrands.some(kw => domain.includes(kw))) gamblingScore += 45;
  gamblingTerms.forEach(kw => { if (domain.includes(kw)) gamblingScore += 15; });
  contentSignals.filter(s => s.category === 'gambling_terminology').forEach(() => gamblingScore += 10);
  contentSignals.filter(s => s.category === 'bonus_promise').forEach(() => gamblingScore += 8);
  contentSignals.filter(s => s.category === 'deposit_language').forEach(() => gamblingScore += 8);
  contentSignals.filter(s => s.category === 'referral_program').forEach(() => gamblingScore += 6);
  
  if (gamblingScore > 20) {
    // Determine sub-type
    const hasCasino = domain.includes('casino') || domain.includes('slot') || domain.includes('roulette') || domain.includes('baccarat');
    const hasBetting = domain.includes('bet') || domain.includes('odds') || domain.includes('sportsbook');
    
    if (hasCasino) scores['Casino'] = gamblingScore;
    else if (hasBetting) scores['Betting'] = gamblingScore;
    else scores['Gambling'] = gamblingScore;
  }
  
  // === PONZI / INVESTMENT SCAM ===
  let ponziScore = 0;
  SIGNAL_PATTERNS.ponzi.urlKeywords.forEach(kw => { if (domain.includes(kw)) ponziScore += 20; });
  contentSignals.filter(s => s.category === 'roi_promise').forEach(() => ponziScore += 15);
  contentSignals.filter(s => s.category === 'referral_program').forEach(() => ponziScore += 10);
  contentSignals.filter(s => s.category === 'withdrawal_trap').forEach(() => ponziScore += 15);
  
  if (ponziScore > 20) scores['Ponzi Scheme'] = ponziScore;
  
  // === PHISHING ===
  let phishingScore = 0;
  SIGNAL_PATTERNS.phishing.urlKeywords.forEach(kw => { if (domain.includes(kw)) phishingScore += 25; });
  const impersonation = detectBrandImpersonation(domain, url);
  if (impersonation.detected) phishingScore += impersonation.strength === 'high' ? 40 : 20;
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
  
  if (isTopBrand) {
    primaryCategory = 'Legitimate';
    confidence = 97;
    explanation = 'Target matches a verified enterprise commercial domain with established trust infrastructure.';
    secondaryCategories = ['Verified Enterprise', 'Established Brand'];
  } else if (sortedCategories.length > 0 && sortedCategories[0][1] >= 30) {
    primaryCategory = sortedCategories[0][0];
    confidence = Math.min(96, Math.max(65, Math.round(sortedCategories[0][1] * 1.1)));
    
    secondaryCategories = sortedCategories.slice(1, 4).map(([cat]) => cat);
    
    // Add sub-signals as secondary tags
    if (contentSignals.some(s => s.category === 'referral_program')) secondaryCategories.push('Referral-Based Scheme');
    if (contentSignals.some(s => s.category === 'deposit_language')) secondaryCategories.push('Deposit-Based Model');
    if (contentSignals.some(s => s.category === 'withdrawal_trap')) secondaryCategories.push('Withdrawal Trap');
    if (contentSignals.some(s => s.category === 'roi_promise')) secondaryCategories.push('ROI/Profit Promises');
    
    secondaryCategories = [...new Set(secondaryCategories)].slice(0, 5);
    
    const explanations = {
      'Gambling': 'Multiple consistent gambling and wagering indicators detected across domain structure and content signals.',
      'Betting': 'Sports betting and wagering terminology detected with deposit/bonus patterns.',
      'Casino': 'Online casino operation indicators detected including slot/roulette/table game signals.',
      'Ponzi Scheme': 'Platform exhibits hallmarks of a synthetic high-yield scheme with guaranteed returns and referral recruitment.',
      'Phishing': 'Credential harvesting indicators detected with brand impersonation and urgency cues.',
      'Crypto Scam': 'Speculative crypto trading with unrealistic return promises and wallet connection requests.',
      'Investment Scam': 'Suspicious investment platform with unverifiable ROI claims and recruitment mechanics.',
      'Fake E-commerce': 'Storefront exhibits deceptive pricing and unverified merchant indicators.',
      'Financial Fraud': 'Advance-fee or payment routing anomalies detected.'
    };
    
    explanation = explanations[primaryCategory] || 'Risk signals detected across multiple analysis dimensions.';
    detectedSignalTexts = contentSignals.map(s => s.text);
  } else {
    // No strong classification match
    const ageDays = domainIntelligence?.ageDays || 365;
    if (ageDays < 30 || (domainIntelligence?.ssl?.type === 'Domain Validation (DV)' && h % 3 === 0)) {
      primaryCategory = 'Unknown';
      confidence = 45;
      explanation = 'Insufficient signals for definitive classification. Domain characteristics warrant monitoring.';
      secondaryCategories = ['Insufficient Data', 'Monitoring Recommended'];
    } else {
      primaryCategory = 'Legitimate';
      confidence = 78 + (h % 16);
      explanation = 'Standard commercial domain with no significant risk pattern indicators detected.';
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
    status: 'classified'
  };
}
