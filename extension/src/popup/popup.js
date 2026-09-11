/**
 * SIH-Guard Extension Popup Controller
 */

const API_BASE = 'http://127.0.0.1:8000/api/v1';
const DASHBOARD_BASE = 'http://localhost:8000';

// Synthetic Demo Presets (for instant evaluation/hackathon demo)
const DEMO_PRESETS = {
  paypal: {
    subject: "URGENT: Suspicious activity on your PayPal account - Action Required",
    sender: "PayPal Security Team <security-alert@paypa1-update-security.com>",
    sender_email: "security-alert@paypa1-update-security.com",
    date: new Date().toISOString(),
    body: "Dear Customer,\n\nWe detected unauthorized access to your account from IP address 185.220.101.5. To protect your funds, your account will be permanently suspended within 24 hours unless you verify your identity.\n\nClick the link below to confirm your password and card details immediately:\nhttp://185.220.101.5/login?ref=paypal_verify\n\nFailure to comply will result in account forfeiture.\n\nPayPal Identity Protection Department",
    headers: {
      "Received-SPF": "fail (domain of paypa1-update-security.com does not designate 185.220.101.5 as permitted sender)",
      "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
      "Return-Path": "<bounce@attacker-relay-net.ru>",
      "Received": "from mail.attacker-relay-net.ru (185.220.101.5) by mx.google.com with ESMTPS"
    },
    links: [
      { url: "http://185.220.101.5/login?ref=paypal_verify", text: "Verify Identity Immediately" }
    ]
  },
  m365: {
    subject: "Security Notification: Password expiry scheduled in 2 hours",
    sender: "Microsoft IT Helpdesk <admin@xn--microsft-p2a.com>",
    sender_email: "admin@xn--microsft-p2a.com",
    date: new Date().toISOString(),
    body: "Hello User,\n\nYour corporate Microsoft 365 password expires in 2 hours. To maintain access to your Outlook, OneDrive, and Teams accounts, please retain your current password now by authenticating with our security portal.\n\nKeep Current Password: http://login-microsoftonline.com.account-auth.top/portal\n\nGlobal IT Administrator",
    headers: {
      "Received-SPF": "softfail",
      "Authentication-Results": "spf=softfail; dkim=fail; dmarc=none",
      "Return-Path": "<admin@xn--microsft-p2a.com>",
      "Received": "from server.ru-host.xyz (91.240.118.42) by mx.google.com"
    },
    links: [
      { url: "http://login-microsoftonline.com.account-auth.top/portal", text: "Keep Current Password" }
    ]
  },
  benign: {
    subject: "Your Monthly Cloud Infrastructure Invoice #INV-2026-09",
    sender: "Billing Department <billing@enterprise-cloud-services.com>",
    sender_email: "billing@enterprise-cloud-services.com",
    date: new Date().toISOString(),
    body: "Hi team,\n\nPlease find attached the summary for your monthly cloud infrastructure usage for the billing cycle ending September 2026. The balance has been auto-debited via your primary card on file.\n\nYou can review your detailed usage metrics in the official cloud dashboard:\nhttps://enterprise-cloud-services.com/dashboard/invoices\n\nThank you for choosing Enterprise Cloud Services.\nSupport Team",
    headers: {
      "Received-SPF": "pass (google.com: domain of billing@enterprise-cloud-services.com designates 142.250.190.46 as permitted sender)",
      "Authentication-Results": "spf=pass; dkim=pass header.i=@enterprise-cloud-services.com; dmarc=pass",
      "Return-Path": "<billing@enterprise-cloud-services.com>",
      "Received": "from mail-relay.enterprise-cloud-services.com (142.250.190.46) by mx.google.com with ESMTPS"
    },
    links: [
      { url: "https://enterprise-cloud-services.com/dashboard/invoices", text: "View Cloud Invoices" }
    ]
  }
};

let currentExtractedEmail = null;

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initRipples();
  initTabs();
  initActiveTab();
  initPresets();
  initEmlUpload();
  checkBackendHealth();
  initFooterLink();
});

function initFooterLink() {
  const link = document.getElementById('footerDashboardLink');
  if (link) {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const url = link.href || `${DASHBOARD_BASE}`;
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, '_blank');
      }
    });
  }
}

// Theme switcher (Midnight Signal <-> Glass Light)
function initTheme() {
  const toggleBtn = document.getElementById('themeToggleBtn');
  if (!toggleBtn) return;

  chrome.storage.local.get(['sih_popup_theme'], (result) => {
    const saved = result.sih_popup_theme || 'midnight';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeIcon(saved);
  });

  toggleBtn.addEventListener('click', (e) => {
    e.preventDefault();
    const current = document.documentElement.getAttribute('data-theme') || 'midnight';
    const next = current === 'midnight' ? 'glass' : 'midnight';
    document.documentElement.setAttribute('data-theme', next);
    chrome.storage.local.set({ sih_popup_theme: next });
    updateThemeIcon(next);
  });
}

function updateThemeIcon(theme) {
  const icon = document.querySelector('.theme-icon');
  if (icon) {
    icon.textContent = theme === 'midnight' ? '🌙' : '☀️';
  }
}

// Backend Health Status Check
async function checkBackendHealth() {
  const statusEl = document.getElementById('backendStatus');
  if (!statusEl) return;
  const statusText = statusEl.querySelector('.status-text');

  // Allow user to click status indicator to retry connection
  if (!statusEl.dataset.hasClickListener) {
    statusEl.dataset.hasClickListener = 'true';
    statusEl.style.cursor = 'pointer';
    statusEl.addEventListener('click', () => {
      if (statusText) statusText.textContent = 'Checking...';
      checkBackendHealth();
    });
  }

  try {
    const res = await fetch(`${API_BASE}/health`, { method: 'GET', cache: 'no-store' });
    if (res.ok) {
      statusEl.classList.remove('offline');
      if (statusText) statusText.textContent = 'Protected';
      statusEl.title = 'Backend Online (Port 8000) — Click to re-check';
      return true;
    }
  } catch (e) {
    // Backend offline or unreachable
  }

  statusEl.classList.add('offline');
  if (statusText) statusText.textContent = 'Offline';
  statusEl.title = 'Backend Offline — Please run run_backend.bat (Click to re-check)';
  return false;
}

// Button ripple animation
function initRipples() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn, .tab-btn, .preset-btn, .theme-toggle-btn');
    if (!btn) return;

    const circle = document.createElement('span');
    const d = Math.max(btn.clientWidth, btn.clientHeight);
    circle.style.width = circle.style.height = `${d}px`;
    const rect = btn.getBoundingClientRect();
    circle.style.left = `${e.clientX - rect.left - d / 2}px`;
    circle.style.top = `${e.clientY - rect.top - d / 2}px`;
    circle.className = 'ripple';
    btn.appendChild(circle);
    setTimeout(() => circle.remove(), 600);
  });
}

// Tab navigation with Nimbus pill spring translation
function initTabs() {
  const tabBtns = Array.from(document.querySelectorAll('.tab-btn'));
  const pillBg = document.getElementById('pillBg');

  function updatePill(idx) {
    if (!pillBg || tabBtns.length === 0) return;
    const pct = idx * 100;
    pillBg.style.transform = `translateX(${pct}%)`;
  }

  tabBtns.forEach((btn, idx) => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      updatePill(idx);

      const targetId = btn.getAttribute('data-tab');
      const targetEl = document.getElementById(targetId);
      if (targetEl) targetEl.classList.add('active');
    });
  });

  // Initial pill position
  updatePill(0);
}

// Active Tab
function initActiveTab() {
  const btnAnalyzeActive = document.getElementById('btnAnalyzeActive');
  const metaSubject = document.getElementById('metaSubject');
  const metaSender = document.getElementById('metaSender');

  // Helper: try to get email from content script, with scripting re-injection fallback
  async function tryGetActiveEmail(tabId) {
    return new Promise((resolve) => {
      chrome.tabs.sendMessage(tabId, { action: 'GET_ACTIVE_EMAIL' }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
          // Content script may be stale after extension reload — re-inject and retry
          if (chrome.scripting) {
            chrome.scripting.executeScript({
              target: { tabId: tabId },
              files: ['src/content/gmail_content.js']
            }, () => {
              if (chrome.runtime.lastError) {
                resolve(null);
                return;
              }
              // Wait a moment for content script to initialize, then retry
              setTimeout(() => {
                chrome.tabs.sendMessage(tabId, { action: 'GET_ACTIVE_EMAIL' }, (retryResponse) => {
                  if (chrome.runtime.lastError || !retryResponse || !retryResponse.success) {
                    resolve(null);
                  } else {
                    resolve(retryResponse.data);
                  }
                });
              }, 500);
            });
          } else {
            resolve(null);
          }
        } else {
          resolve(response.data);
        }
      });
    });
  }

  // Try to query active tab for email
  if (chrome && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0] && tabs[0].url && tabs[0].url.includes('mail.google.com')) {
        const data = await tryGetActiveEmail(tabs[0].id);
        if (data) {
          currentExtractedEmail = data;
          metaSubject.innerText = data.subject || 'No Subject';
          metaSender.innerText = data.sender || 'Unknown';
        } else {
          metaSubject.innerText = 'No email open in Gmail tab';
          metaSender.innerText = 'Open an email, then click Analyze below';
        }
      } else {
        metaSubject.innerText = 'Active tab is not Gmail';
        metaSender.innerText = 'Switch to a Gmail tab or use Presets / EML tab';
      }
    });
  }

  btnAnalyzeActive.addEventListener('click', async () => {
    if (currentExtractedEmail) {
      submitAnalysis(currentExtractedEmail);
    } else {
      if (chrome && chrome.tabs && chrome.tabs.query) {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
          if (tabs[0] && tabs[0].url && tabs[0].url.includes('mail.google.com')) {
            const data = await tryGetActiveEmail(tabs[0].id);
            if (data) {
              currentExtractedEmail = data;
              metaSubject.innerText = data.subject;
              metaSender.innerText = data.sender;
              submitAnalysis(data);
            } else {
              alert('Could not detect an open email. Please make sure an email is expanded in Gmail.');
            }
          } else {
            alert('Please navigate to Gmail (mail.google.com) or use the Demo Presets tab!');
          }
        });
      }
    }
  });
}


// Presets Tab
function initPresets() {
  const presetBtns = document.querySelectorAll('.preset-btn');
  presetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const presetKey = btn.getAttribute('data-preset');
      const emailPayload = DEMO_PRESETS[presetKey];
      if (emailPayload) {
        submitAnalysis(emailPayload);
      }
    });
  });
}

// EML / Raw Upload
function initEmlUpload() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const browseLink = document.getElementById('browseLink');
  const btnAnalyzeRaw = document.getElementById('btnAnalyzeRaw');
  const rawText = document.getElementById('rawEmailText');

  browseLink.addEventListener('click', (e) => {
    e.preventDefault();
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) handleFile(file);
  });

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = '#38bdf8';
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.style.borderColor = 'rgba(56, 189, 248, 0.3)';
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'rgba(56, 189, 248, 0.3)';
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });

  btnAnalyzeRaw.addEventListener('click', () => {
    const text = rawText.value.trim();
    if (!text) {
      alert('Please paste email text or headers first.');
      return;
    }
    submitAnalysis({
      subject: "Custom Analyzed Payload",
      sender: "Custom Input",
      body: text,
      date: new Date().toISOString()
    });
  });

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;
      rawText.value = content.substring(0, 1000) + '...';
      submitAnalysis({
        subject: file.name,
        sender: "Uploaded .EML",
        body: content,
        raw_eml: content,
        date: new Date().toISOString()
      });
    };
    reader.readAsText(file);
  }
}

// Submit Analysis
async function submitAnalysis(payload) {
  const loadingView = document.getElementById('loadingView');
  const resultView = document.getElementById('resultView');

  loadingView.style.display = 'block';
  resultView.style.display = 'none';

  try {
    let result = null;

    // Send via Chrome runtime or direct fetch
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'ANALYZE_EMAIL', payload }, resolve);
      });
      if (response && response.data) {
        result = response.data;
      }
    }

    // Fallback direct fetch if background wasn't available
    if (!result) {
      const res = await fetch(`${API_BASE}/analyze/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      result = await res.json();
    }

    renderResult(result);
  } catch (err) {
    console.log('[SIH-Guard] Analysis notice:', err.message || err);
    alert('Failed to connect to SIH-Guard Backend. Please ensure backend is running at http://localhost:8000.');
  } finally {
    loadingView.style.display = 'none';
  }
}

// Render Results
function renderResult(result) {
  const resultView = document.getElementById('resultView');
  const scoreValue = document.getElementById('scoreValue');
  const scoreCircle = document.getElementById('scoreCircle');
  const verdictClassification = document.getElementById('verdictClassification');
  const explanationText = document.getElementById('explanationText');
  const sigNLPVal = document.getElementById('sigNLPVal');
  const sigAuthVal = document.getElementById('sigAuthVal');
  const sigUrlsVal = document.getElementById('sigUrlsVal');
  const sigGeoVal = document.getElementById('sigGeoVal');
  const btnOpenDashboard = document.getElementById('btnOpenDashboard');

  const score = Math.round(result.threat_score || 0);
  const isCritical = score >= 50;
  const isSuspicious = score >= 25 && score < 50;

  scoreValue.innerText = score;
  
  if (isCritical) {
    scoreCircle.style.borderColor = 'var(--risk-critical)';
    verdictClassification.style.color = '#fb7185';
    verdictClassification.innerText = `HIGH RISK • ${(result.classification || 'MALICIOUS').toUpperCase()}`;
  } else if (isSuspicious) {
    scoreCircle.style.borderColor = 'var(--risk-suspicious)';
    verdictClassification.style.color = '#fbbf24';
    verdictClassification.innerText = `SUSPICIOUS • ${(result.classification || 'CAUTION').toUpperCase()}`;
  } else {
    scoreCircle.style.borderColor = 'var(--risk-safe)';
    verdictClassification.style.color = '#34d399';
    verdictClassification.innerText = `SAFE • ${(result.classification || 'AUTHENTIC').toUpperCase()}`;
  }

  // Humanize explanation text
  let expl = result.explanation || 'No security threat indicators detected.';
  expl = expl
    .replace(/^Safe risk \(Score [0-9.]+\/100\) because\s*/i, 'Verified Safe: ')
    .replace(/^Phishing risk \(Score [0-9.]+\/100\) because\s*/i, 'Security Alert: ')
    .replace(/^Suspicious risk \(Score [0-9.]+\/100\) because\s*/i, 'Caution: ')
    .replace(/^Malicious risk \(Score [0-9.]+\/100\) because\s*/i, 'Critical Risk: ');
  explanationText.innerText = expl;

  // Populate signals
  if (result.signals) {
    sigNLPVal.innerText = result.signals.nlp_urgency || 'Normal';
    sigAuthVal.innerText = result.signals.auth_status || 'Pass';
    sigUrlsVal.innerText = result.signals.malicious_urls_count || '0';
    if (result.geo && result.geo.ip) {
      sigGeoVal.innerText = `${result.geo.country || 'Global'} (${result.geo.ip})`;
      sigGeoVal.title = `IP: ${result.geo.ip} | ISP: ${result.geo.isp || 'N/A'}`;
    } else {
      sigGeoVal.innerText = result.signals.origin_country || 'Global';
    }
  } else {
    sigNLPVal.innerText = score > 50 ? 'Urgent / Coercive' : 'Normal';
    sigAuthVal.innerText = score > 60 ? 'Fail / Mismatch' : 'Pass';
    sigUrlsVal.innerText = result.iocs ? result.iocs.filter(i => i.type === 'url' && i.risk === 'high').length : 0;
    if (result.geo && result.geo.ip) {
      sigGeoVal.innerText = `${result.geo.country || 'Global'} (${result.geo.ip})`;
    } else {
      sigGeoVal.innerText = result.geo ? result.geo.country || 'Global' : 'Global';
    }
  }

  // Set dashboard URL
  const investigationId = result.id || result.investigation_id || 1;
  const targetUrl = `${DASHBOARD_BASE}/investigations/${investigationId}`;
  btnOpenDashboard.href = targetUrl;
  btnOpenDashboard.onclick = (e) => {
    e.preventDefault();
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  };

  resultView.style.display = 'flex';
}

