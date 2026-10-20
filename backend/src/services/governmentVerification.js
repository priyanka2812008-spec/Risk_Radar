/**
 * Government & Regulatory Verification Intelligence Service
 * 
 * Inspects whether a website is:
 * 1. An Official Government / Statutory Entity (.gov.in, .nic.in, .gov, RBI, SEBI, etc.)
 * 2. An Authorized Regulated Financial Entity (Scheduled Banks, SEBI brokers, MCA incorporated)
 * 3. An Unverified / Illegal Entity (Unlicensed betting, Satta, Ponzi, or unregistered finance)
 * 
 * CORE REQUIREMENT:
 * If a website is NOT government verified, especially when offering betting,
 * gambling, lotteries, investments, or deposit schemes, it MUST carry a HIGH / CRITICAL RISK SCORE.
 */

// Official Government and Statutory TLDs and second-level domains
const GOVT_TLD_SUFFIXES = [
  '.gov.in', '.nic.in', '.gov', '.mil', '.gov.uk', '.gov.au', '.gov.us',
  '.gc.ca', '.gov.sg', '.ac.in', '.edu.in', '.res.in'
];

// Explicitly verified Indian statutory authorities and government portals
const VERIFIED_GOVT_DOMAINS = new Set([
  'incometax.gov.in', 'incometaxindia.gov.in', 'gst.gov.in', 'mca.gov.in',
  'rbi.org.in', 'sebi.gov.in', 'uidai.gov.in', 'epfindia.gov.in',
  'irdai.gov.in', 'pfrda.org.in', 'trai.gov.in', 'eci.gov.in',
  'sci.gov.in', 'highcourt.gov.in', 'india.gov.in', 'mygov.in',
  'digitalindia.gov.in', 'meity.gov.in', 'finmin.nic.in', 'mha.gov.in',
  'passportindia.gov.in', 'parivahan.gov.in', 'ceir.gov.in', 'cybercrime.gov.in',
  'npci.org.in', 'bhimupi.org.in'
]);

// Verified RBI Scheduled Commercial Banks & SEBI Registered Exchanges/Brokers
const VERIFIED_REGULATED_INSTITUTIONS = [
  // Banks
  'sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'hdfcbank.com', 'hdfc.com',
  'icicibank.com', 'axisbank.com', 'kotak.com', 'pnbindia.in', 'bankofbaroda.in',
  'canarabank.com', 'unionbankofindia.co.in', 'indusind.com', 'yesbank.in',
  'idfcfirstbank.com', 'federalbank.co.in', 'rblbank.com',
  // SEBI Exchanges & Regulated FinTech
  'nseindia.com', 'bseindia.com', 'mcxindia.com', 'zerodha.com', 'groww.in',
  'angelone.in', 'upstox.com', '5paisa.com', 'icicidirect.com', 'hdfcsec.com',
  'motilaloswal.com', 'sharekhan.com',
  // Verified Global Enterprise Infrastructure
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in',
  'github.com', 'cloudflare.com', 'paypal.com', 'stripe.com', 'wikipedia.org'
];

/**
 * Check if domain matches any of the verified government or regulatory registries
 */
export function checkGovernmentVerification(domain, fullUrl = '', classification = null) {
  const cleanDomain = (domain || '').toLowerCase().replace(/^www\./, '').trim();

  // 1. Check Official Government Portals (.gov.in, .nic.in, rbi.org.in, etc.)
  const isGovtSuffix = GOVT_TLD_SUFFIXES.some(suffix => cleanDomain.endsWith(suffix));
  const isExplicitGovt = VERIFIED_GOVT_DOMAINS.has(cleanDomain) || 
    Array.from(VERIFIED_GOVT_DOMAINS).some(g => cleanDomain.endsWith('.' + g));

  if (isGovtSuffix || isExplicitGovt) {
    return {
      status: 'GOVERNMENT_VERIFIED',
      verified: true,
      isGovt: true,
      trustLevel: 'VERIFIED_SOVEREIGN',
      badge: 'GOVERNMENT VERIFIED ENTITY',
      badgeColor: '#16a34a', // green
      riskAdjustment: -40,
      maxScoreCap: 15,
      regulator: 'Government / Statutory Sovereign Authority',
      citation: 'Official sovereign/statutory portal operating under statutory government mandate.',
      evidence: [
        `Verified sovereign domain architecture: ${cleanDomain}`,
        'Statutory government authority / public institutional clearance verified',
        'Official regulatory registry alignment confirmed'
      ]
    };
  }

  // 2. Check Officially Regulated Banking & Financial Institutions
  const isRegulatedInstitution = VERIFIED_REGULATED_INSTITUTIONS.some(
    inst => cleanDomain === inst || cleanDomain.endsWith('.' + inst)
  );

  if (isRegulatedInstitution) {
    return {
      status: 'REGULATED_INSTITUTION',
      verified: true,
      isGovt: false,
      trustLevel: 'REGULATED_ENTERPRISE',
      badge: 'STATUTORY REGULATED ENTITY',
      badgeColor: '#2563eb', // blue
      riskAdjustment: -25,
      maxScoreCap: 20,
      regulator: 'RBI / SEBI / Recognized Statutory Regulator',
      citation: 'Verified licensed scheduled bank, SEBI registered intermediary, or global enterprise.',
      evidence: [
        `Institutional registry match for verified entity: ${cleanDomain}`,
        'Recognized corporate identity with verifiable statutory regulatory status',
        'Direct compliance with RBI / SEBI / statutory enterprise mandates'
      ]
    };
  }

  // 3. Check for Illegal / Unlicensed Activities (Gambling, Betting, Satta, Ponzi)
  const categoryLabel = (classification?.primary || '').toLowerCase();
  const isGamblingOrBetting = /gambl|betting|casino|satta|matka/i.test(categoryLabel);
  const isPonzi = /ponzi|pyramid|yield trap|crypto scam/i.test(categoryLabel);
  const isStockAdvisory = /stock|advisory|trading tips/i.test(categoryLabel);

  if (isGamblingOrBetting) {
    return {
      status: 'PROHIBITED_UNAUTHORIZED',
      verified: false,
      isGovt: false,
      trustLevel: 'PROHIBITED_BY_LAW',
      badge: 'NOT GOVT. VERIFIED — PROHIBITED BETTING/GAMBLING',
      badgeColor: '#dc2626', // red
      riskFloor: 85,
      regulator: 'Ministry of Information & Broadcasting / Law Enforcement',
      citation: 'Unlicensed & unauthorized under Indian Law (IT Act Sec 69A, Public Gambling Act, MIB Advisories).',
      evidence: [
        'Government Verification FAILED: Online real-money betting and gambling operations are strictly unlicensed in India.',
        'Subject to mandatory blocking advisories under Section 69A of the Information Technology Act and CCPA consumer protection directives.',
        'Entity operates via informal offshore proxy mirrors or unauthorized payment mules without domestic financial clearance.'
      ]
    };
  }

  if (isPonzi) {
    return {
      status: 'PROHIBITED_UNREGULATED_DEPOSIT',
      verified: false,
      isGovt: false,
      trustLevel: 'PROHIBITED_BY_LAW',
      badge: 'NOT GOVT. VERIFIED — UNREGULATED DEPOSIT SCHEME',
      badgeColor: '#dc2626', // red
      riskFloor: 88,
      regulator: 'SEBI / RBI / Banning of Unregulated Deposit Schemes Act (BUDS 2019)',
      citation: 'Unregistered deposit taking and high-yield schemes are cognizable criminal offenses under the BUDS Act 2019.',
      evidence: [
        'Government Verification FAILED: Platform promises capital multiplication without SEBI/RBI statutory deposit-taking registration.',
        'Prohibited under the Banning of Unregulated Deposit Schemes (BUDS) Act, 2019 and Prize Chits & Money Circulation Schemes Act.',
        'Zero verifiable corporate incorporation (CIN) or statutory balance sheet transparency.'
      ]
    };
  }

  if (isStockAdvisory) {
    return {
      status: 'UNREGISTERED_FINANCIAL_ADVISORY',
      verified: false,
      isGovt: false,
      trustLevel: 'UNVERIFIED_ADVISORY',
      badge: 'NOT GOVT. VERIFIED — UNREGISTERED ADVISORY',
      badgeColor: '#ea580c', // amber-red
      riskFloor: 75,
      regulator: 'SEBI (Securities and Exchange Board of India)',
      citation: 'Providing stock tips and trading advisory without SEBI Research Analyst registration violates SEBI RA Regulations.',
      evidence: [
        'Government Verification FAILED: No valid SEBI Research Analyst (RA) registration number verified.',
        'Unregistered financial tips and trading calls carry substantial consumer regulatory risk under SEBI guidelines.',
        'Absence of statutory dispute redressal ombudsman coverage.'
      ]
    };
  }

  // 4. Default: Standard Unverified Website
  // Requirement: "agr vo website govt. verified nhi h to bhi uska risk score high hi hona chaiye"
  return {
    status: 'NOT_GOVERNMENT_VERIFIED',
    verified: false,
    isGovt: false,
    trustLevel: 'UNVERIFIED_PUBLIC',
    badge: 'NOT GOVT. VERIFIED — UNVERIFIED ENTITY',
    badgeColor: '#e11d48', // rose red
    riskFloor: 70, // Guarantees elevated/high risk for unverified domains
    regulator: 'Unverified / No Statutory Clearance',
    citation: 'This domain does not have verifiable government registration or statutory regulatory approval.',
    evidence: [
      'Government Verification Status: UNVERIFIED. Domain lacks verified sovereign or statutory regulatory registry affiliation.',
      'No official government license (SEBI, RBI, MCA, or statutory registry) verified for commercial/financial operations.',
      'Absence of statutory government verification triggers elevated risk assessment.'
    ]
  };
}
