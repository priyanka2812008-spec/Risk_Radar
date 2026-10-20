/**
 * Live Telemetry & Threat Intelligence Collector
 * 
 * Performs real-time server-side forensic inspection of target websites:
 * 1. Safe HTTP/HTTPS fetch with timeout & redirect tracing (no browser JS execution)
 * 2. Real DOM/HTML analysis: Title, meta tags, forms, input types, external links
 * 3. Real DNS resolution: A, NS, MX, TXT records
 * 4. Real TLS/SSL certificate inspection: Issuer, validity, expiry
 * 5. Real RDAP/WHOIS lookup for actual domain age and registration tenure
 * 6. Forensic signal extraction across Satta/Matka, Gambling, Phishing, Ponzi, Stock Advisory, and Brand Spoofing
 */

import dns from 'dns';
import tls from 'tls';
import { promisify } from 'util';

const resolve4 = promisify(dns.resolve4).bind(dns);
const resolveNs = promisify(dns.resolveNs).bind(dns);
const resolveMx = promisify(dns.resolveMx).bind(dns);
const resolveTxt = promisify(dns.resolveTxt).bind(dns);

/**
 * Common major brands to check for impersonation
 */
const NOTABLE_BRANDS = [
  { name: 'State Bank of India', tokens: ['sbi', 'state bank of india', 'onlinesbi'], officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'] },
  { name: 'HDFC Bank', tokens: ['hdfc', 'hdfcbank'], officialDomains: ['hdfcbank.com', 'hdfc.com'] },
  { name: 'ICICI Bank', tokens: ['icici', 'icicibank'], officialDomains: ['icicibank.com'] },
  { name: 'Paytm', tokens: ['paytm'], officialDomains: ['paytm.com'] },
  { name: 'PhonePe', tokens: ['phonepe'], officialDomains: ['phonepe.com'] },
  { name: 'Google', tokens: ['google', 'gmail'], officialDomains: ['google.com', 'google.co.in', 'gmail.com'] },
  { name: 'Microsoft', tokens: ['microsoft', 'outlook', 'office365', 'windows'], officialDomains: ['microsoft.com', 'live.com', 'office.com'] },
  { name: 'Apple', tokens: ['apple', 'icloud'], officialDomains: ['apple.com', 'icloud.com'] },
  { name: 'Amazon', tokens: ['amazon'], officialDomains: ['amazon.com', 'amazon.in'] },
  { name: 'Flipkart', tokens: ['flipkart'], officialDomains: ['flipkart.com'] },
  { name: 'Netflix', tokens: ['netflix'], officialDomains: ['netflix.com'] },
  { name: 'PayPal', tokens: ['paypal'], officialDomains: ['paypal.com'] },
  { name: 'Meta / Facebook', tokens: ['facebook', 'instagram', 'whatsapp', 'meta'], officialDomains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com'] },
  { name: 'Binance', tokens: ['binance'], officialDomains: ['binance.com'] },
  { name: 'Crypto.com', tokens: ['crypto.com'], officialDomains: ['crypto.com'] }
];

/**
 * Keyword dictionaries for live content classification
 */
const PATTERNS = {
  sattaMatka: [
    'satta', 'matka', 'dpboss', 'kalyan matka', 'milan day', 'milan night',
    'rajdhani day', 'rajdhani night', 'satta king', 'desawar', 'gali satta',
    'disawar', 'jodi chart', 'panna chart', 'open close', 'fix game', 'sure matka',
    'sattamatka', 'kalyan chart', 'main ratan', 'madhur day', 'time bazar'
  ],
  gamblingCasino: [
    '1xbet', 'bet365', 'parimatch', 'dafabet', 'stake.com', 'melbet', 'betway',
    'online casino', 'live casino', 'sportsbook', 'cricket betting', 'ipl betting',
    'aviator game', 'color prediction', 'teen patti', 'teenpatti', 'rummy online',
    'roulette', 'baccarat', 'slot machine', 'deposit bonus', '100% bonus',
    'claim bonus', 'free spins', 'win real cash', 'daman games', 'bdg win',
    'fastwin', 'tiranga game', 'tc lottery', 'ok win'
  ],
  ponziYield: [
    'guaranteed return', 'daily return', 'daily profit', 'daily roi', '100% profit',
    'double your money', 'fast cash', 'passive income', 'mining yield',
    'cloud mining', 'risk-free investment', 'referral commission', 'level income',
    'team commission', 'matrix plan', 'pyramid', 'multi-level', 'join downline',
    'withdrawal tax', 'unfreeze fee', 'activation deposit'
  ],
  phishingHarvesting: [
    'account suspended', 'kyc update', 'verify your account', 'pan card update',
    'link aadhaar', 'electricity bill update', 'power disconnected', 'lottery winner',
    'congratulations you won', 'enter otp', 'enter upi pin', 'atm card blocked',
    'verify netbanking', 'confirm your password', 'wallet recovery phrase', 'seed phrase'
  ],
  stockTipsAdvisory: [
    'stock tips', 'sure shot call', 'jackpot call', 'bank nifty tips', 'intraday calls',
    'option trading calls', 'guaranteed profit in stock', 'multibagger stock',
    'sebi registered research analyst', 'stock market classes', 'share trading institute',
    'telegram channel for tips', 'paid advisory'
  ]
};

/**
 * High risk and disposable TLDs
 */
const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'click', 'cfd', 'sbs', 'win', 'bet', 'vip', 'buzz', 'icu',
  'cc', 'online', 'rest', 'link', 'work', 'loan', 'club', 'gq', 'cf', 'tk', 'ml', 'ga'
]);

/**
 * Fetch real DNS records for domain
 */
async function inspectDns(domain) {
  const result = {
    a: [],
    ns: [],
    mx: [],
    txt: [],
    hasMx: false,
    hasSpf: false,
    hasDmarc: false,
    resolved: false,
    error: null
  };

  try {
    const [aRes, nsRes, mxRes, txtRes] = await Promise.allSettled([
      resolve4(domain),
      resolveNs(domain),
      resolveMx(domain),
      resolveTxt(domain)
    ]);

    if (aRes.status === 'fulfilled' && Array.isArray(aRes.value)) {
      result.a = aRes.value;
      result.resolved = true;
    }
    if (nsRes.status === 'fulfilled' && Array.isArray(nsRes.value)) {
      result.ns = nsRes.value;
      result.resolved = true;
    }
    if (mxRes.status === 'fulfilled' && Array.isArray(mxRes.value)) {
      result.mx = mxRes.value;
      result.hasMx = result.mx.length > 0;
    }
    if (txtRes.status === 'fulfilled' && Array.isArray(txtRes.value)) {
      result.txt = txtRes.value.map(row => (Array.isArray(row) ? row.join(' ') : String(row)));
      result.hasSpf = result.txt.some(t => t.toLowerCase().includes('v=spf1'));
      result.hasDmarc = result.txt.some(t => t.toLowerCase().includes('v=dmarc1'));
    }
  } catch (err) {
    result.error = err.message;
  }

  return result;
}

/**
 * Inspect real TLS/SSL certificate
 */
async function inspectTls(domain, port = 443) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect(
      {
        host: domain,
        port,
        servername: domain,
        timeout: 2500,
        rejectUnauthorized: false
      },
      () => {
        if (resolved) return;
        resolved = true;
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;
          socket.end();

          if (!cert || !cert.valid_to) {
            resolve({ valid: false, issuer: 'Unknown', authorized: false, error: 'No certificate presented' });
            return;
          }

          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
          const isExpired = now > validTo;
          const issuerOrg = cert.issuer?.O || cert.issuer?.CN || 'Unknown Certificate Authority';

          resolve({
            valid: authorized && !isExpired,
            authorized,
            authError: authError ? String(authError) : null,
            isExpired,
            issuer: issuerOrg,
            subject: cert.subject?.CN || domain,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining
          });
        } catch (e) {
          resolve({ valid: false, issuer: 'Unknown', authorized: false, error: e.message });
        }
      }
    );

    socket.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        resolve({ valid: false, issuer: 'None', authorized: false, error: err.message });
      }
    });

    socket.on('timeout', () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({ valid: false, issuer: 'None', authorized: false, error: 'TLS connection timeout' });
      }
    });
  });
}

/**
 * Query real RDAP servers for registration date
 */
async function inspectRdap(domain) {
  try {
    const parts = domain.split('.');
    const tld = parts[parts.length - 1];

    let rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    if (['com', 'net'].includes(tld)) {
      rdapUrl = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`;
    }

    const res = await fetch(rdapUrl, {
      headers: { Accept: 'application/json, application/rdap+json' },
      signal: AbortSignal.timeout(2800)
    });

    if (!res.ok) return null;
    const data = await res.json();

    const events = data.events || [];
    const regEvent = events.find(e => ['registration', 'registered'].includes(e.eventAction));
    const expEvent = events.find(e => ['expiration', 'expire'].includes(e.eventAction));

    if (regEvent && regEvent.eventDate) {
      const regDate = new Date(regEvent.eventDate);
      const now = new Date();
      const ageDays = Math.max(0, Math.round((now.getTime() - regDate.getTime()) / (1000 * 60 * 60 * 24)));
      const expDate = expEvent?.eventDate ? new Date(expEvent.eventDate) : null;

      // Extract registrar
      let registrar = 'Verisign/ICANN Accredited Registrar';
      if (Array.isArray(data.entities)) {
        const regEntity = data.entities.find(e => (e.roles || []).includes('registrar'));
        if (regEntity?.vcardArray?.[1]) {
          const fn = regEntity.vcardArray[1].find(item => item[0] === 'fn');
          if (fn && fn[3]) registrar = fn[3];
        }
      }

      return {
        ageDays,
        registrationDate: regDate.toISOString(),
        expirationDate: expDate ? expDate.toISOString() : null,
        registrar,
        source: 'Authoritative RDAP Registry'
      };
    }
  } catch {
    // RDAP unavailable, network restricted, or rate limited
  }
  return null;
}

/**
 * Fetch live webpage and inspect HTML structure, text, and signals
 */
async function fetchAndAnalyzePage(fullUrl, domain) {
  const pageResult = {
    reachable: false,
    httpStatus: null,
    finalUrl: fullUrl,
    title: '',
    metaDescription: '',
    headings: [],
    detectedSignals: [],
    categoriesMatched: [],
    forms: { count: 0, passwordInputs: 0, otpInputs: 0, cardInputs: 0, upiInputs: 0 },
    externalChannels: { telegram: [], whatsapp: [], upi: [], apkLinks: [] },
    brandImpersonation: null,
    bodySample: '',
    error: null
  };

  try {
    const response = await fetch(fullUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,hi;q=0.8'
      },
      signal: AbortSignal.timeout(3500),
      redirect: 'follow'
    });

    pageResult.reachable = true;
    pageResult.httpStatus = response.status;
    pageResult.finalUrl = response.url;

    const html = await response.text();
    const cleanLower = html.toLowerCase();

    // 1. Title Extraction
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    pageResult.title = titleMatch ? titleMatch[1].trim() : '';

    // 2. Meta description
    const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i) ||
                      html.match(/<meta[^>]*content=["']([^"']+)["'][^>]*name=["']description["']/i);
    pageResult.metaDescription = descMatch ? descMatch[1].trim() : '';

    // 3. Headings
    const h1Matches = [...html.matchAll(/<h1[^>]*>([^<]+)<\/h1>/gi)].map(m => m[1].trim()).slice(0, 3);
    const h2Matches = [...html.matchAll(/<h2[^>]*>([^<]+)<\/h2>/gi)].map(m => m[1].trim()).slice(0, 3);
    pageResult.headings = [...h1Matches, ...h2Matches];

    // Combine text for content analysis
    const allText = `${domain} ${pageResult.title} ${pageResult.metaDescription} ${pageResult.headings.join(' ')} ${cleanLower}`.toLowerCase();
    pageResult.bodySample = (pageResult.title + ' ' + pageResult.metaDescription).substring(0, 200);

    const isVerifiedPlatform = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
      'cloudflare.com', 'wikipedia.org', 'paypal.com', 'stripe.com', 'netflix.com',
      'crypto.com', 'binance.com', 'coinbase.com', 'kraken.com', 'linkedin.com',
      'twitter.com', 'x.com', 'youtube.com', 'reddit.com', 'yahoo.com'
    ].some(b => domain === b || domain.endsWith('.' + b));

    // 4. Pattern Matching with False Positive Guardrails
    for (const [catName, keywords] of Object.entries(PATTERNS)) {
      if (isVerifiedPlatform && (catName === 'ponziYield' || catName === 'phishingHarvesting' || catName === 'sattaMatka')) {
        continue; // Verified enterprise platforms do not trigger generic keyword hits
      }
      const hits = keywords.filter(kw => allText.includes(kw));
      // For Ponzi, require at least 2 indicators or a strong guaranteed/double money claim
      const strongPonzi = ['guaranteed return', 'daily return', 'daily profit', 'daily roi', '100% profit', 'double your money', 'unfreeze fee', 'withdrawal tax'];
      const hasStrongPonzi = hits.some(h => strongPonzi.includes(h));
      const minHits = catName === 'ponziYield' ? (hasStrongPonzi ? 1 : 2) : 1;

      if (hits.length >= minHits) {
        pageResult.categoriesMatched.push({
          category: catName,
          count: hits.length,
          matchedKeywords: hits.slice(0, 6)
        });
        pageResult.detectedSignals.push(
          `${catName}: matched ${hits.length} indicator(s) [${hits.slice(0, 4).join(', ')}]`
        );
      }
    }

    // 5. Form & Input Inspection
    const passwordMatch = html.match(/type=["']password["']/gi);
    if (passwordMatch) pageResult.forms.passwordInputs = passwordMatch.length;

    const otpMatch = cleanLower.match(/name=["'][^"']*otp[^"']*["']|placeholder=["'][^"']*otp[^"']*["']/gi);
    if (otpMatch) pageResult.forms.otpInputs = otpMatch.length;

    const cardMatch = cleanLower.match(/name=["'][^"']*(cvv|cardnumber|cc-number)[^"']*["']/gi);
    if (cardMatch) pageResult.forms.cardInputs = cardMatch.length;

    const upiMatch = cleanLower.match(/name=["'][^"']*upi[^"']*["']|placeholder=["'][^"']*vpa[^"']*["']/gi);
    if (upiMatch) pageResult.forms.upiInputs = upiMatch.length;

    // 6. External Communication Channels
    const tgMatches = [...cleanLower.matchAll(/(https?:\/\/t\.me\/[a-zA-Z0-9_+]+)/g)].map(m => m[1]);
    const waMatches = [...cleanLower.matchAll(/(https?:\/\/(wa\.me|api\.whatsapp\.com\/send)[^\s"'<>]+)/g)].map(m => m[1]);
    const apkMatches = [...cleanLower.matchAll(/(https?:[^\s"'<>]+\.apk\b)/g)].map(m => m[1]);

    pageResult.externalChannels.telegram = [...new Set(tgMatches)].slice(0, 3);
    pageResult.externalChannels.whatsapp = [...new Set(waMatches)].slice(0, 3);
    pageResult.externalChannels.apkLinks = [...new Set(apkMatches)].slice(0, 3);

    // 7. Brand Impersonation Detection
    for (const brand of NOTABLE_BRANDS) {
      const isOfficial = brand.officialDomains.some(d => domain === d || domain.endsWith('.' + d));
      if (!isOfficial) {
        const titleOrDomainHasBrand = brand.tokens.some(t => 
          domain.includes(t) || 
          pageResult.title.toLowerCase().includes(t) ||
          pageResult.metaDescription.toLowerCase().includes(t)
        );
        if (titleOrDomainHasBrand) {
          pageResult.brandImpersonation = {
            brand: brand.name,
            targetDomain: domain,
            officialDomains: brand.officialDomains,
            reason: `Site title or domain references brand "${brand.name}" but domain is not an official domain (${brand.officialDomains.join(', ')}).`
          };
          pageResult.detectedSignals.push(`Potential Brand Impersonation: Claims/resembles ${brand.name}`);
          break;
        }
      }
    }
  } catch (err) {
    pageResult.reachable = false;
    pageResult.error = err.message;
  }

  return pageResult;
}

/**
 * Main telemetry aggregator: Combines Live Fetch, DNS, TLS, and RDAP
 */
export async function collectLiveTelemetry(targetUrl, domain) {
  const parts = domain.toLowerCase().split('.');
  const tld = parts[parts.length - 1];

  // Run in parallel for high speed (<3 seconds total)
  const [dnsResult, tlsResult, rdapResult, pageResult] = await Promise.all([
    inspectDns(domain),
    inspectTls(domain),
    inspectRdap(domain),
    fetchAndAnalyzePage(targetUrl, domain)
  ]);

  return {
    domain,
    targetUrl,
    tld,
    isHighRiskTld: HIGH_RISK_TLDS.has(tld),
    dns: dnsResult,
    tls: tlsResult,
    rdap: rdapResult,
    page: pageResult,
    timestamp: new Date().toISOString()
  };
}
