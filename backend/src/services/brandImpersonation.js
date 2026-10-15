/**
 * Brand Impersonation Detection
 * Flags hostnames that borrow a well-known brand name without being that brand's
 * official domain, especially when combined with credential/KYC lure words.
 * e.g. sbi-kyc-update.online, paypal-security-update.fake-auth.xyz
 */

const PROTECTED_BRANDS = {
  paypal: ['paypal.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in'],
  hdfc: ['hdfcbank.com', 'hdfc.com'],
  icici: ['icicibank.com', 'icici.bank.in'],
  axis: ['axisbank.com'],
  kotak: ['kotak.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk'],
  apple: ['apple.com', 'icloud.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com'],
  google: ['google.com', 'google.co.in'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  binance: ['binance.com'],
  metamask: ['metamask.io'],
  coinbase: ['coinbase.com'],
  flipkart: ['flipkart.com'],
  irctc: ['irctc.co.in'],
  incometax: ['incometax.gov.in']
};

const LURE_WORDS = [
  'login', 'signin', 'verify', 'verification', 'kyc', 'update', 'secure', 'security',
  'account', 'wallet', 'unlock', 'suspended', 'confirm', 'auth', 'reward', 'refund', 'support'
];

const tokenize = (value) => (value || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

export function detectBrandImpersonation(domain, url = '') {
  const host = (domain || '').toLowerCase().replace(/^www\./, '');
  const hostTokens = tokenize(host);
  let pathTokens = [];
  try {
    pathTokens = tokenize(new URL(url).pathname);
  } catch {
    pathTokens = [];
  }

  for (const [brand, officialDomains] of Object.entries(PROTECTED_BRANDS)) {
    if (!hostTokens.includes(brand)) continue;
    const isOfficial = officialDomains.some(d => host === d || host.endsWith('.' + d));
    if (isOfficial) return { detected: false };

    const lures = [...new Set([...hostTokens, ...pathTokens].filter(t => LURE_WORDS.includes(t)))];
    return {
      detected: true,
      brand,
      officialDomains,
      lures,
      // A brand name plus a lure word is a much stronger indicator than the brand alone
      strength: lures.length > 0 ? 'high' : 'medium'
    };
  }

  return { detected: false };
}
