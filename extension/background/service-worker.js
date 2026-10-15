/**
 * Risk Radar Extension Background Service Worker (Manifest V3)
 * Manages background intelligence queries, badge states, and local telemetry cache.
 */

const DEFAULT_API_URL = 'http://localhost:5000/api';

// On extension installed or updated
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['apiBaseUrl', 'recentScans', 'highRiskThreshold'], (result) => {
    if (!result.apiBaseUrl) {
      chrome.storage.local.set({ apiBaseUrl: DEFAULT_API_URL });
    }
    if (!result.recentScans) {
      chrome.storage.local.set({ recentScans: [] });
    }
    if (!result.highRiskThreshold) {
      chrome.storage.local.set({ highRiskThreshold: 60 });
    }
  });
  console.log('[Risk Radar] Extension service worker installed.');
});

// Update extension icon badge depending on score
function updateBadge(tabId, score, riskLevel) {
  if (!tabId || score === undefined) return;

  const scoreText = score.toString();
  chrome.action.setBadgeText({ tabId, text: scoreText });

  let badgeColor = '#10b981'; // green for LOW
  if (score > 60) {
    badgeColor = '#ef4444'; // red for HIGH / CRITICAL
  } else if (score > 30) {
    badgeColor = '#f59e0b'; // amber for MEDIUM
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'UPDATE_BADGE') {
    updateBadge(message.tabId, message.score, message.riskLevel);
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'CLEAR_BADGE') {
    if (message.tabId) {
      chrome.action.setBadgeText({ tabId: message.tabId, text: '' });
    }
    sendResponse({ success: true });
    return true;
  }
});
