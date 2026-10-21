/**
 * Risk Radar — Browser Extension Popup Logic (Manifest V3)
 * Automatically detects current tab, analyzes URL through Risk Radar backend,
 * and renders evidence-based risk telemetry without user copy-pasting.
 */

const DEFAULT_API_BASE = 'https://risk-radar-vmtp.onrender.com/api';
let currentActiveTab = null;
let currentTargetUrl = '';
let currentTargetDomain = '';
let currentScanData = null;
let apiBaseUrl = DEFAULT_API_BASE;
let highRiskThreshold = 60;

// DOM Elements
const activeDomainEl = document.getElementById('activeDomain');
const copyUrlBtn = document.getElementById('copyUrlBtn');
const historyBtn = document.getElementById('historyBtn');
const settingsBtn = document.getElementById('settingsBtn');

const loadingView = document.getElementById('loadingView');
const loadingDomainText = document.getElementById('loadingDomainText');
const restrictedView = document.getElementById('restrictedView');
const offlineView = document.getElementById('offlineView');
const offlineApiUrl = document.getElementById('offlineApiUrl');
const offlineRetryBtn = document.getElementById('offlineRetryBtn');
const restrictedRetryBtn = document.getElementById('restrictedRetryBtn');

const resultsView = document.getElementById('resultsView');
const highRiskBanner = document.getElementById('highRiskBanner');
const unknownSuspiciousBanner = document.getElementById('unknownSuspiciousBanner');
const scoreGauge = document.getElementById('scoreGauge');
const scoreNumber = document.getElementById('scoreNumber');
const riskLevelText = document.getElementById('riskLevelText');
const riskStatusLabel = document.getElementById('riskStatusLabel');
const lastScannedText = document.getElementById('lastScannedText');

const confidencePill = document.getElementById('confidencePill');
const classificationPrimary = document.getElementById('classificationPrimary');
const classificationExplanation = document.getElementById('classificationExplanation');

const signalsList = document.getElementById('signalsList');
const signalsCountBadge = document.getElementById('signalsCountBadge');

const identityLevelBadge = document.getElementById('identityLevelBadge');
const idBusiness = document.getElementById('idBusiness');
const idEmail = document.getElementById('idEmail');
const idPhone = document.getElementById('idPhone');
const idAddress = document.getElementById('idAddress');
const messagingWarning = document.getElementById('messagingWarning');

const viewPassportBtn = document.getElementById('viewPassportBtn');
const openFullReportBtn = document.getElementById('openFullReportBtn');
const rescanBtn = document.getElementById('rescanBtn');
const verificationTokenLabel = document.getElementById('verificationTokenLabel');

const passportModal = document.getElementById('passportModal');
const closePassportBtn = document.getElementById('closePassportBtn');
const passDomain = document.getElementById('passDomain');
const passToken = document.getElementById('passToken');
const passAge = document.getElementById('passAge');
const passRegistrar = document.getElementById('passRegistrar');
const passIp = document.getElementById('passIp');
const passAsn = document.getElementById('passAsn');
const passCountry = document.getElementById('passCountry');
const passSsl = document.getElementById('passSsl');
const passRecommendation = document.getElementById('passRecommendation');

const historyDrawer = document.getElementById('historyDrawer');
const closeHistoryBtn = document.getElementById('closeHistoryBtn');
const historyList = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

const settingsModal = document.getElementById('settingsModal');
const closeSettingsBtn = document.getElementById('closeSettingsBtn');
const settingApiUrl = document.getElementById('settingApiUrl');
const settingThreshold = document.getElementById('settingThreshold');
const saveSettingsBtn = document.getElementById('saveSettingsBtn');

// Progress checklist items
const checkItems = [
  document.getElementById('check-norm'),
  document.getElementById('check-domain'),
  document.getElementById('check-threat'),
  document.getElementById('check-content'),
  document.getElementById('check-scoring')
];

/**
 * Clean and normalize URL to core domain
 */
function extractDomain(urlStr) {
  try {
    const parsed = new URL(urlStr);
    return parsed.hostname.toLowerCase();
  } catch {
    return urlStr.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0];
  }
}

/**
 * Remove tracking parameters like utm_*, ref, gclid for clean analysis
 */
function cleanTrackingUrl(urlStr) {
  try {
    const url = new URL(urlStr);
    const trackingParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', '_ga'];
    trackingParams.forEach(p => url.searchParams.delete(p));
    return url.toString();
  } catch {
    return urlStr;
  }
}

/**
 * Update progressive loading animation
 */
function runChecklistAnimation(callback) {
  checkItems.forEach(el => {
    el.className = 'check-item';
    el.querySelector('.check-icon').textContent = '○';
  });

  let current = 0;
  const interval = setInterval(() => {
    if (current > 0) {
      checkItems[current - 1].className = 'check-item done';
      checkItems[current - 1].querySelector('.check-icon').textContent = '✓';
    }
    if (current < checkItems.length) {
      checkItems[current].className = 'check-item current';
      checkItems[current].querySelector('.check-icon').textContent = '●';
      current++;
    } else {
      clearInterval(interval);
      if (callback) callback();
    }
  }, 240);

  return interval;
}

/**
 * Set score colors
 */
function getScoreColor(score) {
  if (score <= 30) return '#10b981'; // emerald
  if (score <= 60) return '#f59e0b'; // amber
  return '#ef4444'; // rose / critical
}

/**
 * Switch view visibility
 */
function showView(view) {
  loadingView.classList.add('hidden');
  restrictedView.classList.add('hidden');
  offlineView.classList.add('hidden');
  resultsView.classList.add('hidden');

  if (view === 'loading') loadingView.classList.remove('hidden');
  else if (view === 'restricted') restrictedView.classList.remove('hidden');
  else if (view === 'offline') offlineView.classList.remove('hidden');
  else if (view === 'results') resultsView.classList.remove('hidden');
}

/**
 * Perform analysis by sending active tab URL to Risk Radar backend
 */
async function analyzeCurrentWebsite(targetUrl) {
  showView('loading');
  loadingDomainText.textContent = `Analyzing ${currentTargetDomain}`;

  let animationDone = false;
  let apiResponse = null;
  let apiError = null;

  runChecklistAnimation(() => {
    animationDone = true;
    if (apiResponse) {
      renderResults(apiResponse);
    } else if (apiError) {
      handleApiError(apiError);
    }
  });

  try {
    const res = await fetch(`${apiBaseUrl}/analyze-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!res.ok) {
      throw new Error(`HTTP error ${res.status}`);
    }

    const data = await res.json();
    apiResponse = data;

    if (animationDone) {
      renderResults(data);
    }
  } catch (err) {
    console.error('[Risk Radar Extension] Backend error:', err);
    apiError = err;
    if (animationDone) {
      handleApiError(err);
    }
  }
}

/**
 * Handle API failure
 */
function handleApiError(err) {
  offlineApiUrl.textContent = apiBaseUrl;
  showView('offline');
}

/**
 * Render complete forensic telemetry
 */
function renderResults(data) {
  currentScanData = data;
  showView('results');

  // Score & Level
  scoreNumber.textContent = data.riskScore;
  const scoreColor = getScoreColor(data.riskScore);
  scoreGauge.style.borderColor = scoreColor;
  riskLevelText.textContent = `${data.riskLevel} RISK`;
  riskLevelText.style.color = scoreColor;
  riskStatusLabel.textContent = data.statusLabel || (data.riskScore > 60 ? 'Suspicious Posture' : 'Normal Posture');
  lastScannedText.textContent = `Last scanned: Just now`;

  // Warning Banners
  if (data.riskScore >= highRiskThreshold) {
    highRiskBanner.classList.remove('hidden');
  } else {
    highRiskBanner.classList.add('hidden');
  }

  if (data.unknownSuspicious) {
    unknownSuspiciousBanner.classList.remove('hidden');
  } else {
    unknownSuspiciousBanner.classList.add('hidden');
  }

  // Classification & Confidence
  classificationPrimary.textContent = data.classification || 'Unclassified';
  confidencePill.textContent = `Confidence: ${data.confidencePercent || Math.round((data.confidence || 0.8) * 100)}%`;
  classificationExplanation.textContent = data.explanation || 'Multi-vector telemetry analysis concluded.';

  // Signals List
  signalsList.innerHTML = '';
  if (Array.isArray(data.signals) && data.signals.length > 0) {
    signalsCountBadge.textContent = `${data.signals.length} Signals`;
    data.signals.forEach(sig => {
      const row = document.createElement('div');
      row.className = 'signal-row';

      const isDetected = sig.status === 'Detected';
      const icon = isDetected ? '⚠️' : '✓';
      const sevClass = sig.severity === 'CRITICAL' ? 'sev-critical' : (sig.severity === 'HIGH' ? 'sev-high' : (sig.severity === 'MEDIUM' ? 'sev-med' : 'sev-low'));

      row.innerHTML = `
        <span class="signal-icon-tag">${icon}</span>
        <div class="signal-body">
          <div class="signal-title-row">
            <span class="signal-cat">${sig.category}</span>
            <span class="severity-pill ${sevClass}">${sig.severity}</span>
          </div>
          <div class="signal-desc">${sig.explanation}</div>
        </div>
      `;
      signalsList.appendChild(row);
    });
  }

  // Contact Identity
  const contact = data.contactAnalysis || {};
  const idLevel = contact.level || 'MEDIUM';
  identityLevelBadge.textContent = idLevel;
  identityLevelBadge.className = `identity-badge ${idLevel.toLowerCase()}`;

  idBusiness.textContent = contact.businessEmailMatch ? 'Verified Domain' : 'Unverified';
  idEmail.textContent = contact.primaryEmail ? contact.primaryEmail : 'None Found';
  idPhone.textContent = contact.phoneDetected ? 'Detected' : 'Not Found';
  idAddress.textContent = contact.addressDetected ? 'Detected' : 'Not Found';

  if (contact.messagingOnly) {
    messagingWarning.classList.remove('hidden');
  } else {
    messagingWarning.classList.add('hidden');
  }

  // Token
  verificationTokenLabel.textContent = data.verificationToken || 'RR-2026';

  // Populate Passport
  populatePassport(data);

  // Save to History & Update Tab Badge
  saveToHistory(data);
  if (currentActiveTab && currentActiveTab.id) {
    chrome.runtime.sendMessage({
      type: 'UPDATE_BADGE',
      tabId: currentActiveTab.id,
      score: data.riskScore,
      riskLevel: data.riskLevel
    });
  }
}

/**
 * Populate Digital Risk Passport modal
 */
function populatePassport(data) {
  passDomain.textContent = data.domain || currentTargetDomain;
  passToken.textContent = data.verificationToken || 'RR-2026-TOKEN';
  passAge.textContent = `${data.domainIntelligence?.ageDays ?? '--'} days old`;
  passRegistrar.textContent = data.domainIntelligence?.registrar || 'Unknown Registrar';
  passIp.textContent = data.domainIntelligence?.ipAddress || '0.0.0.0';
  passAsn.textContent = `${data.domainIntelligence?.asn?.asn || 'AS0'} (${data.domainIntelligence?.hostingProvider || 'Unknown'})`;
  passCountry.textContent = data.domainIntelligence?.country || 'Global';
  passSsl.textContent = data.domainIntelligence?.ssl?.type || 'TLS Standard';
  passRecommendation.textContent = data.recommendation || 'Exercise standard browsing caution.';
}

// Resilient Storage Adapter (chrome.storage.local with localStorage fallback)
const storage = {
  get: (keys, callback) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(keys, callback);
    } else {
      const result = {};
      keys.forEach(k => {
        try {
          const val = localStorage.getItem('riskradar_' + k);
          if (val !== null) result[k] = JSON.parse(val);
        } catch {
          // ignore parsing error
        }
      });
      callback(result);
    }
  },
  set: (items, callback) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set(items, callback);
    } else {
      Object.entries(items).forEach(([k, v]) => {
        try {
          localStorage.setItem('riskradar_' + k, JSON.stringify(v));
        } catch {
          // ignore quota error
        }
      });
      if (callback) callback();
    }
  }
};

/**
 * Save scan to local history in storage
 */
function saveToHistory(data) {
  storage.get(['recentScans'], (result) => {
    const list = result.recentScans || [];
    const filtered = list.filter(item => item.domain !== data.domain);
    const newEntry = {
      domain: data.domain,
      url: data.url,
      score: data.riskScore,
      riskLevel: data.riskLevel,
      classification: data.classification,
      timestamp: new Date().toISOString()
    };
    filtered.unshift(newEntry);
    storage.set({ recentScans: filtered.slice(0, 25) });
  });
}

/**
 * Load and render recent scans
 */
function renderHistory() {
  storage.get(['recentScans'], (result) => {
    const list = result.recentScans || [];
    historyList.innerHTML = '';
    if (list.length === 0) {
      historyList.innerHTML = '<div style="color:#64748b; font-size:11px; padding:12px; text-align:center;">No recent scans recorded.</div>';
      return;
    }

    list.forEach(item => {
      const itemEl = document.createElement('div');
      itemEl.className = 'history-item';
      const color = getScoreColor(item.score);
      itemEl.innerHTML = `
        <div>
          <div class="history-domain">${item.domain}</div>
          <div style="font-size:10px; color:#64748b;">${item.classification || 'Unknown'}</div>
        </div>
        <span class="history-score-badge" style="background-color: ${color}22; color: ${color}; border: 1px solid ${color}44;">
          ${item.score} ${item.riskLevel}
        </span>
      `;
      itemEl.addEventListener('click', () => {
        historyDrawer.classList.add('hidden');
        currentTargetDomain = item.domain;
        currentTargetUrl = item.url;
        activeDomainEl.textContent = currentTargetDomain;
        analyzeCurrentWebsite(currentTargetUrl);
      });
      historyList.appendChild(itemEl);
    });
  });
}

/**
 * Capture current active tab in Chrome/Edge
 */
function captureActiveTab() {
  if (!chrome.tabs) {
    // Fallback in standalone test environment
    currentTargetDomain = 'instant-bonus-pay.cc';
    currentTargetUrl = 'https://instant-bonus-pay.cc/claim-bonus';
    activeDomainEl.textContent = currentTargetDomain;
    analyzeCurrentWebsite(currentTargetUrl);
    return;
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      showView('restricted');
      return;
    }

    currentActiveTab = tabs[0];
    const url = currentActiveTab.url || '';

    // Check for restricted schemes (chrome://, file://, localhost, about:)
    if (!url || !url.startsWith('http://') && !url.startsWith('https://')) {
      activeDomainEl.textContent = 'Restricted Protocol';
      showView('restricted');
      return;
    }

    const domain = extractDomain(url);
    if (domain === 'localhost' || domain === '127.0.0.1') {
      activeDomainEl.textContent = domain;
      showView('restricted');
      return;
    }

    currentTargetDomain = domain;
    currentTargetUrl = cleanTrackingUrl(url);
    activeDomainEl.textContent = currentTargetDomain;

    // Start auto analysis immediately without user typing or pasting
    analyzeCurrentWebsite(currentTargetUrl);
  });
}

// =========================================================
// EVENT LISTENERS
// =========================================================

// Copy domain button
copyUrlBtn.addEventListener('click', () => {
  if (!currentTargetDomain) return;
  navigator.clipboard.writeText(currentTargetDomain);
  copyUrlBtn.style.color = '#10b981';
  setTimeout(() => { copyUrlBtn.style.color = ''; }, 1500);
});

// Re-scan button
rescanBtn.addEventListener('click', () => {
  if (currentTargetUrl) {
    analyzeCurrentWebsite(currentTargetUrl);
  } else {
    captureActiveTab();
  }
});

// Retry buttons
offlineRetryBtn.addEventListener('click', () => {
  if (currentTargetUrl) analyzeCurrentWebsite(currentTargetUrl);
  else captureActiveTab();
});

restrictedRetryBtn.addEventListener('click', () => {
  captureActiveTab();
});

// Open Full Report in web app
openFullReportBtn.addEventListener('click', () => {
  const target = currentTargetDomain || currentTargetUrl;
  const webAppUrl = `http://localhost:5173/?scan=${encodeURIComponent(target)}`;
  if (chrome.tabs) {
    chrome.tabs.create({ url: webAppUrl });
  } else {
    window.open(webAppUrl, '_blank');
  }
});

// Digital Risk Passport Modal
viewPassportBtn.addEventListener('click', () => {
  passportModal.classList.remove('hidden');
});
closePassportBtn.addEventListener('click', () => {
  passportModal.classList.add('hidden');
});
passportModal.addEventListener('click', (e) => {
  if (e.target === passportModal) passportModal.classList.add('hidden');
});

// Recent Scans History Drawer
historyBtn.addEventListener('click', () => {
  renderHistory();
  historyDrawer.classList.remove('hidden');
});
closeHistoryBtn.addEventListener('click', () => {
  historyDrawer.classList.add('hidden');
});
clearHistoryBtn.addEventListener('click', () => {
  storage.set({ recentScans: [] }, () => {
    renderHistory();
  });
});
historyDrawer.addEventListener('click', (e) => {
  if (e.target === historyDrawer) historyDrawer.classList.add('hidden');
});

// Settings Modal
settingsBtn.addEventListener('click', () => {
  settingApiUrl.value = apiBaseUrl;
  settingThreshold.value = highRiskThreshold;
  settingsModal.classList.remove('hidden');
});
closeSettingsBtn.addEventListener('click', () => {
  settingsModal.classList.add('hidden');
});
saveSettingsBtn.addEventListener('click', () => {
  const urlVal = settingApiUrl.value.trim();
  const threshVal = parseInt(settingThreshold.value, 10);
  if (urlVal) apiBaseUrl = urlVal;
  if (!isNaN(threshVal)) highRiskThreshold = threshVal;

  storage.set({ apiBaseUrl, highRiskThreshold }, () => {
    settingsModal.classList.add('hidden');
    if (currentTargetUrl) analyzeCurrentWebsite(currentTargetUrl);
  });
});
settingsModal.addEventListener('click', (e) => {
  if (e.target === settingsModal) settingsModal.classList.add('hidden');
});

// =========================================================
// INITIALIZATION
// =========================================================
document.addEventListener('DOMContentLoaded', () => {
  storage.get(['apiBaseUrl', 'highRiskThreshold'], (result) => {
    if (result && result.apiBaseUrl) apiBaseUrl = result.apiBaseUrl;
    if (result && result.highRiskThreshold) highRiskThreshold = result.highRiskThreshold;
    captureActiveTab();
  });
});
