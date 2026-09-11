/**
 * SIH-Guard Background Service Worker (Manifest V3)
 */

const API_ENDPOINTS = [
  'http://127.0.0.1:8000/api/v1/analyze/email',
  'http://localhost:8000/api/v1/analyze/email'
];

// Listen for messages from Content Script or Popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'ANALYZE_EMAIL') {
    handleAnalyzeEmail(request.payload)
      .then((data) => {
        // Update badge
        updateBadge(data);
        sendResponse({ success: true, data });
      })
      .catch((error) => {
        console.log('[SIH-Guard Background] Analysis notice:', error.message || error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep channel open for async response
  }
});

async function handleAnalyzeEmail(payload) {
  let lastError = null;
  for (const endpoint of API_ENDPOINTS) {
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        return await response.json();
      }
      lastError = new Error(`API error: HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError || new Error('Failed to connect to backend on port 8000.');
}

function updateBadge(result) {
  if (!chrome.action) return;

  const score = Math.round(result.threat_score || 0);
  const cls = (result.classification || '').toUpperCase();

  let text = '';
  let color = '#10b981'; // safe green

  if (score >= 75 || cls === 'MALICIOUS' || cls === 'PHISHING') {
    text = `${score}`;
    color = '#ef4444'; // critical red
  } else if (score >= 40 || cls === 'SUSPICIOUS') {
    text = `${score}`;
    color = '#f59e0b'; // warning orange
  } else {
    text = 'OK';
    color = '#10b981';
  }

  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// Keep-alive heartbeat & auto-injection for Gmail tabs
async function injectIntoOpenGmailTabs() {
  try {
    const tabs = await chrome.tabs.query({ url: '*://mail.google.com/*' });
    for (const tab of tabs) {
      if (tab.id) {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['src/content/gmail_content.js']
        }).catch(() => {});
        await chrome.scripting.insertCSS({
          target: { tabId: tab.id },
          files: ['src/content/gmail_content.css']
        }).catch(() => {});
      }
    }
  } catch (err) {
    console.log('[SIH-Guard] Tab injection check:', err);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('[SIH-Guard] Service Worker installed/reloaded');
  chrome.alarms.create('sih_keepalive', { periodInMinutes: 0.4 });
  injectIntoOpenGmailTabs();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create('sih_keepalive', { periodInMinutes: 0.4 });
  injectIntoOpenGmailTabs();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'sih_keepalive') {
    // Keep-alive ping
  }
});

console.log('[SIH-Guard] Service Worker initialized.');
