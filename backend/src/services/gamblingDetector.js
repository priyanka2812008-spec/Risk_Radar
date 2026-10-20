/**
 * Exhaustive Gambling, Betting, Casino, Satta Matka & Ponzi Detection Engine
 * 
 * Accurately detects:
 * - Real-world Indian & International betting syndicates & exchanges (Lotus365, Winbuzz, MahadevBook, Fairplay, Daman, Fastwin, etc.)
 * - Satta Matka portals (Dpboss, Kalyan, Satta King, Milan Day, Gali Desawar, etc.)
 * - Casino & slot games (Aviator, Teen Patti, Color Prediction, Roulette, Blackjack, etc.)
 * - Betting exchange and proxy mirror patterns (exch99, laser247, silverexch, skyexchange, etc.)
 * - Ponzi schemes & high-yield investment traps (Guaranteed ROI, Crypto doubling, Metaforce, etc.)
 */

// Comprehensive dictionary of known betting brands and platforms
export const BETTING_GAMBLING_BRANDS = [
  // Famous Indian illegal betting syndicates & apps
  'lotus365', 'winbuzz', 'mahadevbook', 'mahadev', 'fairplay', 'fairplay24',
  'radheexchange', 'laser247', 'silverexch', 'skyexchange', 'betbhai9',
  'cricbet99', '99exch', 'fastwin', 'bdgwin', 'daman', 'damangames',
  'tc-lottery', 'tclottery', 'tiranga', 'okwin', 'diuwin', 'babu88',
  'jeetbuzz', 'bajilive', 'khelraja', 'megapari', 'melbet', 'wolf777',
  'playbazaar', 'cricketbet9', 'cricketbetting', 'iplbet', 'iplwin',
  'sattaking', 'satta-king', 'dpboss', 'kalyan', 'matka', 'disawar', 'desawar',
  'gali-satta', 'milan-day', 'milan-night', 'rajdhani-day', 'rajdhani-night',
  'time-bazar', 'madhur-day', 'main-ratan', 'fix-matka', 'surematka',
  // Major International betting / crypto casino platforms
  '1xbet', 'bet365', 'parimatch', 'dafabet', 'stake', 'stakegames',
  'melbet', 'betway', 'betking', 'mostbet', 'linebet', 'purewin',
  'roobet', 'rollbit', 'bcgame', 'bc.game', 'shuffle', 'gamdom',
  'duelbits', 'blaze', 'pokerstars', '888casino', 'betano', 'bwin',
  'betfair', 'ladbrokes', 'williamhill', 'casumo', 'betvictor',
  'unibet', 'pinnacle', 'marathonbet', 'sportingbet', 'betsson'
];

// Keywords and tokens in domain, subdomain, path or search query
export const GAMBLING_KEYWORDS = [
  'bet', 'betting', 'bets', 'casino', 'gambling', 'poker', 'sportsbook',
  'slot', 'slots', 'roulette', 'wager', 'wagering', 'baccarat', 'bookmaker',
  'odds', 'jackpot', 'exchange', 'exch', 'bookie', 'lottery', 'lotto',
  'satta', 'matka', 'dpboss', 'kalyan', 'aviator', 'colorprediction',
  'color-prediction', 'teenpatti', 'teen-patti', 'rummy', 'andarbahar',
  'andar-bahar', 'jodi', 'panna', 'desawar', 'disawar', 'cricketbet',
  'livebet', 'live-bet', 'inplay', 'in-play', 'bookmaker'
];

// High-Risk Gambling TLDs
export const GAMBLING_TLDS = new Set([
  'bet', 'casino', 'poker', 'games', 'win', 'vip', 'bingo'
]);

// Ponzi, High-Yield Investment & Capital Trap Lexicon
export const PONZI_KEYWORDS = [
  'profit', 'crypto-yield', 'double', 'fastcash', 'guaranteed-return',
  '100x', 'daily-return', 'passive-income', 'daily-crypto-roi', 'roi-1000',
  'high-yield', 'yield-farm', 'liquidity-pool-guarantee', 'fixed-apy',
  'referral-bonus', 'pyramid', 'downstream-earning', 'recruit-to-earn',
  'unfreeze-tax', 'clearance-fee', 'crowd-sharing', 'metaforce', 'forsage',
  'matrix-plan', 'multilevel', 'generation-income', 'level-income',
  'doubleyourmoney', 'doublemoney', 'instant-profit', 'crypto-multiplier',
  'smart-contract-income', 'tron-matrix', 'eth-matrix', 'mining-yield',
  'cloud-mining-returns', 'guaranteed-profit', 'risk-free-investment'
];

/**
 * Perform deep forensic detection on a target URL
 */
export function detectGamblingOrPonzi(domain, fullUrl = '', liveTelemetry = null) {
  const cleanDomain = (domain || '').toLowerCase().replace(/^www\./, '').trim();
  const cleanUrl = (fullUrl || cleanDomain).toLowerCase();

  const parts = cleanDomain.split('.');
  const sld = parts.length > 2 ? parts[parts.length - 2] : parts[0];
  const tld = parts[parts.length - 1];

  const matchedPatterns = [];
  let isGambling = false;
  let isSatta = false;
  let isBetting = false;
  let isCasino = false;
  let isPonzi = false;
  let confidence = 0;
  let reason = '';

  // 1. Check Known Betting & Gambling Brands
  for (const brand of BETTING_GAMBLING_BRANDS) {
    if (cleanDomain.includes(brand) || cleanUrl.includes(brand)) {
      matchedPatterns.push(`Known betting syndicate/brand token: "${brand}"`);
      if (['dpboss', 'kalyan', 'matka', 'satta', 'disawar', 'desawar', 'milan', 'rajdhani'].some(s => brand.includes(s))) {
        isSatta = true;
      } else {
        isBetting = true;
      }
      isGambling = true;
      confidence = Math.max(confidence, 96);
    }
  }

  // 2. Check Satta Matka terminology
  const sattaKeywords = ['satta', 'matka', 'dpboss', 'kalyan', 'disawar', 'desawar', 'jodi-chart', 'panna-chart'];
  if (sattaKeywords.some(kw => cleanDomain.includes(kw) || cleanUrl.includes(kw))) {
    isSatta = true;
    isGambling = true;
    matchedPatterns.push('Satta Matka wagering terminology in domain structure');
    confidence = Math.max(confidence, 98);
  }

  // 3. Check Regex Patterns for Betting Exchanges & Mirror Networks
  // e.g. laser247, silverexch, 99exch, cricbet99, skyexchange, radheexchange
  const exchRegex = /[a-z0-9]*(exch|exchange|book|bet|win|buzz)[0-9]*/i;
  if (exchRegex.test(cleanDomain)) {
    const match = cleanDomain.match(exchRegex);
    if (match && match[0].length >= 4) {
      const token = match[1].toLowerCase();
      if (['exch', 'exchange', 'book', 'bet'].includes(token) || 
          (['win', 'buzz'].includes(token) && /[0-9]/.test(cleanDomain))) {
        isBetting = true;
        isGambling = true;
        matchedPatterns.push(`Betting exchange / bookmaker domain pattern: "${match[0]}"`);
        confidence = Math.max(confidence, 94);
      }
    }
  }

  // 4. Check Gambling Lexicon
  for (const kw of GAMBLING_KEYWORDS) {
    if (cleanDomain.includes(kw) || cleanUrl.includes(kw)) {
      if (['casino', 'slot', 'roulette', 'baccarat', 'teenpatti'].includes(kw)) isCasino = true;
      else if (['bet', 'sportsbook', 'odds', 'bookmaker'].includes(kw)) isBetting = true;
      isGambling = true;
      matchedPatterns.push(`Gambling/wagering keyword: "${kw}"`);
      confidence = Math.max(confidence, 90);
    }
  }

  // 5. Check High-Risk Gambling TLDs (.bet, .casino, .win, etc.)
  if (GAMBLING_TLDS.has(tld)) {
    isGambling = true;
    matchedPatterns.push(`Operating under dedicated gambling TLD: .${tld}`);
    confidence = Math.max(confidence, 92);
  }

  // 6. Check Ponzi / High-Yield Scheme Lexicon
  for (const kw of PONZI_KEYWORDS) {
    if (cleanDomain.includes(kw) || cleanUrl.includes(kw)) {
      isPonzi = true;
      matchedPatterns.push(`High-yield / Ponzi return promise indicator: "${kw}"`);
      confidence = Math.max(confidence, 94);
    }
  }

  // 7. Check Live Telemetry page analysis (DOM text, categories matched, headings)
  if (liveTelemetry?.page) {
    const page = liveTelemetry.page;
    if (page.categoriesMatched?.some(c => c.category === 'sattaMatka')) {
      isSatta = true;
      isGambling = true;
      matchedPatterns.push('Live page content contains Satta Matka result charts and game numbers');
      confidence = Math.max(confidence, 98);
    }
    if (page.categoriesMatched?.some(c => c.category === 'gamblingCasino')) {
      isGambling = true;
      matchedPatterns.push('Live page content contains real-money wagering, casino games, and bonus lures');
      confidence = Math.max(confidence, 96);
    }
    if (page.categoriesMatched?.some(c => c.category === 'ponziYield')) {
      isPonzi = true;
      matchedPatterns.push('Live page contains high-yield return promises and multi-level recruitment mechanics');
      confidence = Math.max(confidence, 96);
    }
  }

  // Determine Primary Category
  let category = null;
  if (isSatta) {
    category = 'Satta / Matka Gambling';
    reason = 'Platform operates an illegal Satta Matka betting portal publishing Kalyan/Disawar results and wager schemes.';
  } else if (isCasino) {
    category = 'Casino';
    reason = 'Online casino gaming platform detected with slot, roulette, or table game wagering operations.';
  } else if (isBetting) {
    category = 'Betting';
    reason = 'Real-money sportsbook or betting exchange operation detected with wagering odds.';
  } else if (isGambling) {
    category = 'Gambling';
    reason = 'Multiple consistent gambling and wagering indicators identified across domain structure.';
  } else if (isPonzi) {
    category = 'Ponzi Scheme';
    reason = 'Platform exhibits hallmarks of a synthetic high-yield investment scheme with guaranteed returns.';
  }

  return {
    isDetected: isGambling || isPonzi,
    isGambling,
    isSatta,
    isBetting,
    isCasino,
    isPonzi,
    category,
    confidence: confidence || (isGambling || isPonzi ? 92 : 0),
    matchedPatterns,
    reason
  };
}
