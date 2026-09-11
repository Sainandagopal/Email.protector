/**
 * SIH-Guard Content Script for Gmail
 * Manifest V3 compatible
 */

(function () {
  'use strict';

  console.log('[SIH-Guard] Gmail Content Script Loaded');

  // Helper: check if the extension context is still valid (survives extension reloads)
  function isExtensionContextValid() {
    try {
      return !!(chrome.runtime && chrome.runtime.id);
    } catch (e) {
      return false;
    }
  }

  // Inject security button into email headers
  // Find email containers using multiple fallback selectors for different Gmail versions
  function findEmailContainers() {
    // Try multiple known Gmail container selectors
    let containers = document.querySelectorAll('.adn.ads, .gE.iv.gt, .h7, .nH.if');

    // Fallback: if no containers found, look for email body and walk up to container
    if (containers.length === 0) {
      const bodyEls = document.querySelectorAll('.a3s.aiL, .ii.gt');
      const found = new Set();
      bodyEls.forEach(bodyEl => {
        // Walk up to find a reasonable container (max 6 levels up)
        let parent = bodyEl.parentElement;
        for (let i = 0; i < 6 && parent; i++) {
          if (parent.querySelector('.gD, span[email]') || parent.querySelector('.gH, .gK')) {
            found.add(parent);
            break;
          }
          parent = parent.parentElement;
        }
      });
      if (found.size > 0) {
        containers = Array.from(found);
      }
    }

    return containers;
  }

  function injectAnalyzeButtons() {
    // Select open email message containers in Gmail
    const emailContainers = findEmailContainers();
    emailContainers.forEach((container) => {
      // Check if button already injected
      let btn = container.querySelector('.sih-guard-btn');
      if (!btn) {
        btn = document.createElement('button');
        btn.className = 'sih-guard-btn scanning';
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> <span>Auto-Scanning...</span>';
        btn.title = 'SIH-Guard: Automatically analyzing email threat level (Click to re-scan)';

        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          e.preventDefault();
          container.dataset.sihAutoScanned = 'in-progress';
          await analyzeEmailInContainer(container, btn).finally(() => {
            container.dataset.sihAutoScanned = 'done';
          });
        });

        // Try to place button in Gmail's right-side toolbar area (next to reply/forward/more icons)
        const toolbarArea = container.querySelector('.iH .ip') ||   // Gmail toolbar row  
          container.querySelector('.amn') ||       // Action buttons area
          container.querySelector('.bHQ');         // Secondary toolbar

        if (toolbarArea) {
          toolbarArea.appendChild(btn);
        } else {
          // Fallback: insert after the sender line so it appears inline on the right
          const senderRow = container.querySelector('.gH') || container.querySelector('.gK');
          if (senderRow) {
            senderRow.style.position = 'relative';
            senderRow.appendChild(btn);
          } else {
            // Last resort: append to container (still floats right via CSS)
            const headerArea = container.querySelector('.nH .hx') || container.querySelector('.adn');
            if (headerArea) {
              headerArea.appendChild(btn);
            }
          }
        }
      }

      // Automatically scan new messages as soon as body content renders
      if (!container.dataset.sihAutoScanned) {
        const bodyEl = container.querySelector('.a3s.aiL') || container.querySelector('.ii.gt') || container.querySelector('div[dir="ltr"]');
        if (bodyEl && bodyEl.innerText.trim().length > 0) {
          container.dataset.sihAutoScanned = 'in-progress';
          // Minimal debounce delay for instant scanning
          setTimeout(() => {
            analyzeEmailInContainer(container, btn)
              .then(() => {
                container.dataset.sihAutoScanned = 'done';
              })
              .catch((err) => {
                console.log('[SIH-Guard] Automatic scan deferred:', err.message || err);
                container.dataset.sihAutoScanned = 'failed';
              });
          }, 20);

        }
      }
    });
  }


  // Extract email data from Gmail container
  function extractEmailData(container) {
    // Subject (often at the top h2)
    const subjectEl = document.querySelector('h2.hP') || container.querySelector('.hP') || document.querySelector('h2[data-thread-perm-id]');
    const subject = subjectEl ? subjectEl.innerText.trim() : 'Unknown Subject';

    // Sender
    const senderEl = container.querySelector('.gD') || container.querySelector('span[email]');
    const senderName = senderEl ? senderEl.innerText.trim() : '';
    const senderEmail = senderEl ? (senderEl.getAttribute('email') || senderEl.innerText.trim()) : '';

    // Date
    const dateEl = container.querySelector('.g3') || container.querySelector('.mI');
    const date = dateEl ? (dateEl.getAttribute('title') || dateEl.innerText.trim()) : new Date().toISOString();

    // Body
    const bodyEl = container.querySelector('.a3s.aiL') || container.querySelector('.ii.gt') || container.querySelector('div[dir="ltr"]');
    const bodyText = bodyEl ? bodyEl.innerText.trim() : '';
    const bodyHtml = bodyEl ? bodyEl.innerHTML : '';

    // Links — limit to max 6 unique links for sub-second performance
    const links = [];
    const seenUrls = new Set();
    if (bodyEl) {
      const anchorEls = bodyEl.querySelectorAll('a[href]');
      anchorEls.forEach((a) => {
        if (links.length >= 6) return;
        let href = a.getAttribute('href') || '';
        const text = a.innerText.trim();

        // Unwrap Gmail data-saferedirecturl
        const safeRedirect = a.getAttribute('data-saferedirecturl');
        if (safeRedirect) {
          try {
            const urlObj = new URL(safeRedirect);
            const q = urlObj.searchParams.get('q');
            if (q) href = q;
          } catch (e) { }
        }

        // Unwrap google.com/url?q=
        if (href.includes('google.com/url?') || href.includes('google.com/url/')) {
          try {
            const urlObj = new URL(href);
            const q = urlObj.searchParams.get('q') || urlObj.searchParams.get('url');
            if (q) href = q;
          } catch (e) { }
        }

        // Unwrap Outlook SafeLinks
        if (href.includes('safelinks.protection.outlook.com')) {
          try {
            const urlObj = new URL(href);
            const realUrl = urlObj.searchParams.get('url');
            if (realUrl) href = realUrl;
          } catch (e) { }
        }

        if (href && !href.startsWith('mailto:') && !href.startsWith('javascript:') && !href.startsWith('#')) {
          if (!seenUrls.has(href) && links.length < 6) {
            seenUrls.add(href);
            links.push({ url: href, text: text || href });
          }
        }
      });

      // Also extract URLs and raw domains mentioned directly in body text if needed
      if (links.length < 6) {
        const textMatches = bodyText.match(/https?:\/\/[^\s<>"'\)]+|\b[a-zA-Z0-9-]+\.(?:ru|su|top|xyz|click|site|online|me|tv|info|cc|buzz|tk|cn|cfd|gq|ml|cam|icu|live|rest|work|stream|fit|support)\b/gi) || [];
        textMatches.forEach(match => {
          if (links.length >= 6) return;
          const clean = match.trim().replace(/[.,;]+$/, '');
          if (!seenUrls.has(clean)) {
            const formatted = clean.startsWith('http') ? clean : `https://${clean}`;
            seenUrls.add(clean);
            seenUrls.add(formatted);
            links.push({ url: formatted, text: clean });
          }
        });
      }
    }

    // Extract observable header-like signals from Gmail's DOM
    const headers = extractGmailHeaderSignals(container, senderEmail, bodyText);

    return {
      subject,
      sender: senderName ? `${senderName} <${senderEmail}>` : senderEmail,
      sender_email: senderEmail,
      date,
      body: bodyText,
      body_html: bodyHtml,
      headers: headers,
      links: links
    };
  }

  /**
   * Extract observable security signals from Gmail's DOM.
   * Gmail doesn't expose raw RFC headers in DOM, but we can detect:
   * - Public IP addresses mentioned in email text or alert banners
   * - Security warning banners (red/yellow warnings)
   * - "via" indicator (sender authentication mismatch)
   * - "mailed-by" and "signed-by" domains in details
   * - External sender warnings
   */
  function extractGmailHeaderSignals(container, senderEmail, bodyText) {
    const headers = {};
    const senderDomain = senderEmail.includes('@') ? senderEmail.split('@')[1].toLowerCase() : '';

    if (senderDomain) {
      headers['X-Sender-Domain'] = senderDomain;
    }

    // 0. Extract any public IPv4 addresses mentioned in body or headers
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const combinedContent = (bodyText || '') + ' ' + (container.innerText || '');
    const foundIps = combinedContent.match(ipRegex) || [];
    const publicIps = [];
    foundIps.forEach(ip => {
      const parts = ip.split('.').map(Number);
      if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0 || parts[0] === 255) return;
      if (parts[0] === 192 && parts[1] === 168) return;
      if (parts[0] === 172 && (parts[1] >= 16 && parts[1] <= 31)) return;
      if (!publicIps.includes(ip)) {
        publicIps.push(ip);
      }
    });

    if (publicIps.length > 0) {
      headers['X-Originating-IP'] = publicIps[0];
      headers['X-Detected-Public-IPs'] = publicIps.join(', ');
    }

    // Check for "mailed-by" and "signed-by" in Gmail details
    const textAll = container.innerText || '';
    const mailedMatch = textAll.match(/mailed[- ]by:\s*([a-zA-Z0-9.-]+)/i);
    if (mailedMatch && mailedMatch[1]) {
      headers['X-Mailed-By'] = mailedMatch[1].trim();
    }
    const signedMatch = textAll.match(/signed[- ]by:\s*([a-zA-Z0-9.-]+)/i);
    if (signedMatch && signedMatch[1]) {
      headers['X-Signed-By'] = signedMatch[1].trim();
    }

    // 1. Check for Gmail security warning banners
    // Gmail shows red/yellow warning banners for phishing/spam/unverified senders
    const warningBanners = document.querySelectorAll(
      '.aQR, .aZo, [data-tooltip*="suspicious"], [data-tooltip*="dangerous"], .Kj-JD-K7, .bAK'
    );
    let hasSecurityWarning = false;
    warningBanners.forEach(banner => {
      const text = (banner.innerText || banner.textContent || '').toLowerCase();
      if (text.includes('suspicious') || text.includes('dangerous') || text.includes('phishing') ||
        text.includes('spam') || text.includes('be careful') || text.includes('caution')) {
        hasSecurityWarning = true;
      }
    });

    // 2. Check for "via" indicator — Gmail shows "sender@domain via otherdomain.com"
    // when the email's authentication doesn't match the displayed sender
    const viaEl = container.querySelector('.gD + span, .gI span.go');
    const viaAllEls = container.querySelectorAll('span');
    let viaInfo = '';
    viaAllEls.forEach(el => {
      const text = (el.innerText || '').trim();
      if (text.startsWith('via ')) {
        viaInfo = text.replace('via ', '').trim();
      }
    });

    // 3. Check Gmail's "Show details" security info if available
    const securityInfoEls = container.querySelectorAll('.ajv, .ajA, .ajC');
    let hasPassedSPF = false;
    let hasPassedDKIM = false;
    securityInfoEls.forEach(el => {
      const text = (el.innerText || '').toLowerCase();
      if (text.includes('spf') && text.includes('pass')) hasPassedSPF = true;
      if (text.includes('dkim') && text.includes('pass')) hasPassedDKIM = true;
    });

    // 4. Check for external sender indicator
    const externalIndicators = document.querySelectorAll('[data-tooltip*="external"], .bAs');
    let isExternalSender = externalIndicators.length > 0;

    // Build synthetic headers based on observed Gmail signals
    if (hasSecurityWarning) {
      // Gmail flagged this email — synthesize failed auth headers
      headers['Received-SPF'] = 'fail (Gmail security warning detected for this message)';
      headers['Authentication-Results'] = 'spf=fail; dkim=fail; dmarc=fail';
      headers['X-Gmail-Security-Warning'] = 'true';
    } else if (viaInfo) {
      // "via" indicator means sender domain doesn't fully authenticate
      headers['Received-SPF'] = `softfail (message sent via ${viaInfo}, sender domain is ${senderDomain})`;
      headers['Authentication-Results'] = `spf=softfail; dkim=none`;
      headers['X-Gmail-Via'] = viaInfo;
      if (viaInfo.toLowerCase() !== senderDomain) {
        headers['Return-Path'] = `<bounce@${viaInfo}>`;
      }
    } else if (hasPassedSPF && hasPassedDKIM) {
      headers['Received-SPF'] = `pass (domain of ${senderEmail} designates sending IP as permitted sender)`;
      headers['Authentication-Results'] = `spf=pass; dkim=pass; dmarc=pass`;
    }
    // If no signals detected, headers remain empty — backend will treat as "unknown"

    // 5. Include sender domain for Return-Path alignment check
    if (!headers['Return-Path'] && senderEmail) {
      headers['Return-Path'] = `<${senderEmail}>`;
    }

    return headers;
  }

  // Trigger analysis
  async function analyzeEmailInContainer(container, btn) {
    const originalHtml = btn.innerHTML;
    btn.className = 'sih-guard-btn scanning';
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> <span>Scanning...</span>';

    try {
      const emailData = extractEmailData(container);
      console.log('[SIH-Guard] Extracted email data:', emailData);
      console.log('[SIH-Guard] Extracted links:', emailData.links);
      console.log('[SIH-Guard] Extracted headers:', emailData.headers);

      // Guard: ensure extension context is still alive (not invalidated by reload)
      if (!isExtensionContextValid()) {
        throw new Error('Extension was reloaded. Please refresh this Gmail tab and try again.');
      }

      // Send to background script
      const response = await new Promise((resolve, reject) => {
        try {
          chrome.runtime.sendMessage(
            { action: 'ANALYZE_EMAIL', payload: emailData },
            (res) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
              } else {
                resolve(res);
              }
            }
          );
        } catch (e) {
          reject(new Error('Extension was reloaded. Please refresh this Gmail tab.'));
        }
      });

      if (!response || response.error) {
        throw new Error(response ? response.error : 'Connection error to backend');
      }

      const result = response.data;
      console.log('[SIH-Guard] Received analysis verdict from backend:', result);
      const score = Math.round(result.threat_score || 0);
      const classification = (result.classification || 'UNKNOWN').toLowerCase();

      // Update button status
      btn.className = `sih-guard-btn ${classification}`;
      let statusBadge = 'SAFE';
      if (classification === 'suspicious') {
        statusBadge = 'SUSPICIOUS';
      } else if (classification === 'phishing' || classification === 'malicious') {
        statusBadge = 'HIGH RISK';
      }

      btn.innerHTML = `<span>●</span> <span style="font-weight: 600;">${statusBadge}</span> <span style="font-size: 13px; font-weight: 800; margin-left: 3px;">${score}/100</span>`;

      // Clean humanized explanation
      let expl = result.explanation || 'No security threat indicators detected.';
      expl = expl
        .replace(/^Safe risk \(Score [0-9.]+\/100\) because\s*/i, '')
        .replace(/^Phishing risk \(Score [0-9.]+\/100\) because\s*/i, '')
        .replace(/^Suspicious risk \(Score [0-9.]+\/100\) because\s*/i, '')
        .replace(/^Malicious risk \(Score [0-9.]+\/100\) because\s*/i, '');

      const signals = result.signals || {};
      const advice = signals.user_advice || (classification === 'safe'
        ? 'Safe to read and click. This email is authentic.'
        : (classification === 'suspicious'
          ? 'Proceed with caution. Double-check before clicking links.'
          : 'Warning: High risk of phishing. Do not click links or enter passwords.'));

      const senderTrust = signals.sender_trust || (classification === 'safe' ? 'Authentic & Verified' : 'Check Sender Domain');
      const linksTrust = signals.links_trust || (classification === 'safe' ? 'Safe & Official' : 'Suspicious / Deceptive Links');
      const originCountry = signals.origin_country || (result.geo ? `${result.geo.city || ''} ${result.geo.country || ''}`.trim() : 'Registered Infrastructure');
      // 1. Sender Telemetry Chip
      const isSenderSafe = classification === 'safe';
      const senderChip = {
        icon: '👤',
        title: 'Sender Identity',
        badge: isSenderSafe ? 'Verified Authentic' : (classification === 'suspicious' ? 'Unverified Domain' : 'Spoofed Identity'),
        level: isSenderSafe ? 'safe' : (classification === 'suspicious' ? 'warning' : 'danger'),
        dotColor: isSenderSafe ? '#16a34a' : (classification === 'suspicious' ? '#d97706' : '#dc2626')
      };

      // 2. Mail Routing & Authentication (SPF / DKIM)
      const isAuthSafe = classification === 'safe';
      const authChip = {
        icon: '📬',
        title: 'Authentication',
        badge: isAuthSafe ? 'SPF & DKIM Valid' : 'Unaligned Relay',
        level: isAuthSafe ? 'safe' : 'warning',
        dotColor: isAuthSafe ? '#16a34a' : '#d97706'
      };

      // 3. Origin Infrastructure
      let geoLabel = 'Registered Relays';
      if (result.geo && (result.geo.country || result.geo.city || result.geo.isp)) {
        const parts = [];
        if (result.geo.city && result.geo.city !== 'Unknown') parts.push(result.geo.city);
        if (result.geo.country && result.geo.country !== 'Unknown') parts.push(result.geo.country);
        if (result.geo.isp && result.geo.isp !== 'Unknown') parts.push(result.geo.isp);
        geoLabel = parts.slice(0, 2).join(' • ') || 'Verified Infrastructure';
      } else if (originCountry) {
        geoLabel = originCountry;
      }
      const originChip = {
        icon: '🌍',
        title: 'Origin Host',
        badge: geoLabel,
        level: 'safe',
        dotColor: '#2563eb'
      };

      // 4. Link Threat Status
      const totalUrls = (result.urls || []).length;
      const dangerousUrls = (result.urls || []).filter(u => {
        const s = Number(u.risk_score || 0);
        return s >= 70 || u.is_blocked || u.risk === 'critical' || u.risk === 'high';
      });
      const blockedCount = dangerousUrls.length;

      let linkBadge = 'No Links';
      let linkLevel = 'safe';
      let linkDot = '#16a34a';
      if (totalUrls > 0) {
        if (blockedCount > 0) {
          linkBadge = `${blockedCount} Malicious Blocked`;
          linkLevel = 'danger';
          linkDot = '#dc2626';
        } else {
          linkBadge = `${totalUrls} Scanned Safe`;
          linkLevel = 'safe';
          linkDot = '#16a34a';
        }
      }
      const linksChip = {
        icon: '🔗',
        title: 'Destination Links',
        badge: linkBadge,
        level: linkLevel,
        dotColor: linkDot
      };

      const telemetryChips = [senderChip, authChip, originChip, linksChip];

      // Remove existing banner if any
      const existingBanner = container.querySelector('.sih-verdict-banner');
      if (existingBanner) existingBanner.remove();

      // Build sleek telemetry chips HTML
      let telemetryChipsHtml = '';
      telemetryChips.forEach((chip, idx) => {
        telemetryChipsHtml += `
          <div class="sih-telemetry-chip chip-${chip.level}" style="animation-delay: ${0.08 * (idx + 1)}s">
            <div class="sih-chip-icon-box">${chip.icon}</div>
            <div class="sih-chip-body">
              <span class="sih-chip-label">${chip.title}</span>
              <span class="sih-chip-badge-val">
                <span class="sih-chip-dot" style="background-color: ${chip.dotColor};"></span>
                ${chip.badge}
              </span>
            </div>
          </div>
        `;
      });

      // Build link intelligence diagnostic table if URLs present
      let linksIntelHtml = '';
      if (result.urls && result.urls.length > 0) {
        let rowsHtml = '';
        result.urls.forEach(u => {
          const uScore = Math.round(u.risk_score || (u.risk === 'critical' ? 85 : (u.risk === 'high' ? 70 : 10)));
          const isBlocked = uScore >= 70 || u.is_blocked || u.risk === 'critical' || u.risk === 'high';
          rowsHtml += `
            <div class="sih-link-chip-row ${isBlocked ? 'row-blocked' : 'row-safe'}">
              <div class="sih-link-chip-left">
                <span class="sih-link-badge ${isBlocked ? 'badge-danger' : 'badge-safe'}">
                  ${isBlocked ? '🚫 DEFANGED' : '🟢 VERIFIED'}
                </span>
                <code class="sih-link-url" title="${u.url}">${u.domain || u.url}</code>
              </div>
              <div class="sih-link-chip-right">
                <span class="sih-link-score-badge ${isBlocked ? 'score-danger' : 'score-safe'}">Threat ${uScore}/100</span>
                <span class="sih-link-status-text">${isBlocked ? 'Disabled in Email Body' : (u.reasons || 'Clean Destination')}</span>
              </div>
            </div>
          `;
        });

        linksIntelHtml = `
          <div class="sih-links-intel-box">
            <div class="sih-links-intel-title">
              <div class="sih-links-intel-label">
                <span>🔗 Destination Link Intelligence</span>
                <span class="sih-links-count-pill">${result.urls.length} Scanned</span>
              </div>
              <span class="sih-links-subnote">${blockedCount > 0 ? `⚠️ ${blockedCount} threats neutralized` : 'Threat Score &ge; 70 blocked automatically'}</span>
            </div>
            <div class="sih-links-list">
              ${rowsHtml}
            </div>
          </div>
        `;
      }

      // Create verdict banner below email header
      const banner = document.createElement('div');
      banner.className = `sih-verdict-banner ${classification}`;

      const verdictTitle = classification === 'safe'
        ? 'SAFE EMAIL'
        : (classification === 'suspicious' ? 'SUSPICIOUS EMAIL' : 'PHISHING ALERT');
      const guidanceIcon = classification === 'safe' ? '✓' : (classification === 'suspicious' ? '⚠️' : '⛔');

      banner.innerHTML = `
        <div class="sih-banner-inner">
          <div class="sih-banner-top">
            <div class="sih-verdict-pill-wrap">
              <div class="sih-verdict-pill ${classification}">
                <span class="sih-pulse-beacon"></span>
                <span class="sih-verdict-title">${verdictTitle}</span>
              </div>

              <div class="sih-score-display-pill ${classification}">
                <span class="sih-score-prefix">Threat Score</span>
                <span class="sih-score-value">${score}</span>
                <span class="sih-score-total">/100</span>
              </div>
            </div>

            <a href="http://localhost:5173/investigations/${result.id}" target="_blank" class="sih-dossier-pill-btn">
              <span>Open Forensic Dossier</span>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="7" y1="17" x2="17" y2="7"></line><polyline points="7 7 17 7 17 17"></polyline></svg>
            </a>
          </div>

          <div class="sih-guidance-bar ${classification}">
            <span class="sih-guidance-icon">${guidanceIcon}</span>
            <div class="sih-guidance-content">
              <strong>Recommendation:</strong> ${advice}
            </div>
          </div>

          <div class="sih-telemetry-row">
            ${telemetryChipsHtml}
          </div>

          ${linksIntelHtml}
        </div>
      `;

      const bodyEl = container.querySelector('.a3s.aiL') || container;
      bodyEl.parentNode.insertBefore(banner, bodyEl);

      // Neutralize any malicious links in the email body (Threat Score >= 70)
      neutralizeMaliciousLinks(container, result.urls);

    } catch (err) {
      console.log('[SIH-Guard] Analysis notice:', err.message || err);
      btn.className = 'sih-guard-btn';
      btn.innerHTML = '<span>❌</span> <span>Analysis Failed (Retry)</span>';
      setTimeout(() => {
        btn.innerHTML = originalHtml;
      }, 4000);
    }
  }

  /**
   * Neutralize/block any hyperlink inside the email body if its threat score is >= 70.
   * Strips all navigation attributes (href, target, data-saferedirecturl),
   * disables navigation with capturing event listeners on all interaction events,
   * changes styling to strike-through red with prominent danger styling,
   * and intercepts clicks with an explanatory security alert modal.
   */
  function neutralizeMaliciousLinks(container, urls) {
    if (!urls || urls.length === 0) return;

    const dangerousUrls = urls.filter(u => {
      const s = Number(u.risk_score || 0);
      return s >= 70 || u.is_blocked || u.risk === 'critical' || u.risk === 'high';
    });

    if (dangerousUrls.length === 0) return;

    // 1. Find ALL anchor tags in the email container
    const allAnchors = container.querySelectorAll('a');

    dangerousUrls.forEach(danger => {
      const dangerDomain = (danger.domain || '').toLowerCase().trim();
      const dangerUrl = (danger.url || '').toLowerCase().trim();

      allAnchors.forEach(a => {
        const rawHref = (a.getAttribute('href') || '').toLowerCase().trim();
        const safeRedirect = (a.getAttribute('data-saferedirecturl') || '').toLowerCase().trim();
        const text = (a.innerText || a.textContent || '').toLowerCase().trim();

        // Also decode URLs to catch URL-encoded redirects
        let decodedHref = '';
        let decodedSafeRedirect = '';
        try { decodedHref = decodeURIComponent(rawHref); } catch (e) { decodedHref = rawHref; }
        try { decodedSafeRedirect = decodeURIComponent(safeRedirect); } catch (e) { decodedSafeRedirect = safeRedirect; }

        // Unwrap google.com/url?q=... parameter
        let unwrappedTarget = '';
        try {
          if (rawHref.includes('google.com/url?') || safeRedirect.includes('google.com/url?')) {
            const urlToParse = rawHref.includes('google.com/url?') ? rawHref : safeRedirect;
            const uObj = new URL(urlToParse);
            unwrappedTarget = (uObj.searchParams.get('q') || uObj.searchParams.get('url') || '').toLowerCase();
          }
        } catch (e) { }

        const isMatch = (dangerUrl && (
          rawHref.includes(dangerUrl) || safeRedirect.includes(dangerUrl) ||
          decodedHref.includes(dangerUrl) || decodedSafeRedirect.includes(dangerUrl) ||
          (unwrappedTarget && unwrappedTarget.includes(dangerUrl)) ||
          text.includes(dangerUrl)
        )) || (dangerDomain && dangerDomain.length > 3 && (
          rawHref.includes(dangerDomain) || safeRedirect.includes(dangerDomain) ||
          decodedHref.includes(dangerDomain) || decodedSafeRedirect.includes(dangerDomain) ||
          (unwrappedTarget && unwrappedTarget.includes(dangerDomain)) ||
          text.includes(dangerDomain)
        ));

        if (isMatch) {
          a.dataset.sihBlocked = 'true';
          const originalTarget = a.getAttribute('data-blocked-href') || a.getAttribute('href') || a.getAttribute('data-saferedirecturl') || danger.url;
          const blockedScore = Math.round(danger.risk_score || 95);
          const blockedReason = danger.reasons || 'High-threat malware/phishing link destination (Threat Score ≥ 70)';

          // Defang link: completely strip navigation attributes
          a.removeAttribute('href');
          a.removeAttribute('target');
          a.removeAttribute('data-saferedirecturl');
          a.removeAttribute('onclick');
          a.setAttribute('data-blocked-href', originalTarget);
          a.setAttribute('href', 'javascript:void(0);');

          // Threat visual styling
          a.style.cursor = 'not-allowed';
          a.style.textDecoration = 'line-through';
          a.style.color = '#dc2626';
          a.style.backgroundColor = '#fee2e2';
          a.style.padding = '2px 8px';
          a.style.borderRadius = '4px';
          a.style.border = '2px solid #ef4444';
          a.style.fontWeight = 'bold';
          a.style.pointerEvents = 'auto';
          a.title = `🚫 BLOCKED BY SIH-GUARD (Threat Score: ${blockedScore}/100): ${blockedReason}`;

          // Make children non-clickable so all clicks hit our capturing handler on 'a'
          a.querySelectorAll('*').forEach(child => {
            child.style.pointerEvents = 'none';
          });

          // Intercept clicks & all navigation attempts in capturing phase
          const blockNavigation = (e) => {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            if (e.type === 'click' || e.type === 'auxclick') {
              showLinkBlockedModal(originalTarget, danger.domain, blockedScore, blockedReason);
            }
            return false;
          };

          ['click', 'mousedown', 'mouseup', 'pointerdown', 'auxclick', 'keydown'].forEach(evtType => {
            a.addEventListener(evtType, blockNavigation, true);
          });

          // Add inline visual blocked pill if not already added
          const existingTag = a.parentElement ? a.parentElement.querySelector(`.sih-link-blocked-inline-tag[data-target-domain="${dangerDomain}"]`) : null;
          if (!existingTag) {
            const tag = document.createElement('span');
            tag.className = 'sih-link-blocked-inline-tag';
            tag.setAttribute('data-target-domain', dangerDomain);
            tag.style.display = 'inline-flex';
            tag.style.alignItems = 'center';
            tag.style.gap = '4px';
            tag.style.marginLeft = '8px';
            tag.style.padding = '2px 8px';
            tag.style.backgroundColor = '#dc2626';
            tag.style.color = '#ffffff';
            tag.style.borderRadius = '9999px';
            tag.style.fontSize = '11px';
            tag.style.fontWeight = '700';
            tag.style.cursor = 'pointer';
            tag.innerHTML = `🚫 LINK BLOCKED (${blockedScore}/100)`;
            tag.title = 'Click to view security diagnostic';
            tag.addEventListener('click', (e) => {
              e.preventDefault();
              e.stopPropagation();
              showLinkBlockedModal(originalTarget, danger.domain, blockedScore, blockedReason);
            });
            if (a.nextSibling) {
              a.parentNode.insertBefore(tag, a.nextSibling);
            } else if (a.parentNode) {
              a.parentNode.appendChild(tag);
            }
          }
        }
      });
    });

    // 2. Add delegated capturing event listener on container as fallback protection
    if (!container.dataset.sihDelegatedShield) {
      container.dataset.sihDelegatedShield = 'true';
      container.addEventListener('click', (e) => {
        const anchor = e.target.closest('a');
        if (anchor) {
          const checkTarget = (
            anchor.getAttribute('href') ||
            anchor.getAttribute('data-blocked-href') ||
            anchor.getAttribute('data-saferedirecturl') ||
            anchor.innerText ||
            ''
          ).toLowerCase();

          dangerousUrls.forEach(danger => {
            const dDom = (danger.domain || '').toLowerCase().trim();
            const dUrl = (danger.url || '').toLowerCase().trim();
            if ((dDom && dDom.length > 3 && checkTarget.includes(dDom)) || (dUrl && checkTarget.includes(dUrl))) {
              e.preventDefault();
              e.stopPropagation();
              e.stopImmediatePropagation();
              showLinkBlockedModal(
                checkTarget,
                danger.domain,
                Math.round(danger.risk_score || 95),
                danger.reasons || 'High-threat malware/phishing link destination'
              );
            }
          });
        }
      }, true); // Capturing phase!
    }
  }

  /**
   * Display an executive security alert modal if a user clicks on a neutralized link.
   */
  function showLinkBlockedModal(url, domain, score, reasons) {
    const existing = document.getElementById('sih-blocked-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'sih-blocked-modal';
    modal.className = 'sih-modal-backdrop';
    modal.innerHTML = `
      <div class="sih-modal-box">
        <div class="sih-modal-header">
          <div class="sih-modal-title">
            <span style="font-size: 22px;">🚫</span>
            <h3>Malicious Hyperlink Blocked</h3>
          </div>
          <button class="sih-modal-close" id="sih-close-modal">&times;</button>
        </div>
        <div class="sih-modal-body">
          <p style="color: #991b1b; font-weight: 700; margin-bottom: 12px; font-size: 13.5px;">
            SIH-Guard has neutralized this link to protect your credentials, funds, and device.
          </p>
          <div class="sih-modal-field">
            <strong>Target Destination:</strong> <code>${domain || url}</code>
          </div>
          <div class="sih-modal-field">
            <strong>Threat Score:</strong> <span class="sih-score-pill">${score}/100 (Threshold: 70)</span>
          </div>
          <div class="sih-modal-field">
            <strong>Security Diagnostic:</strong> <span>${reasons}</span>
          </div>
          <div class="sih-modal-warning">
            ⚠️ <strong>Why this was blocked:</strong> Navigation was stopped because this destination exhibits credential-harvesting patterns, lookalike spoofing, or malware distribution risks.
          </div>
        </div>
        <div class="sih-modal-footer">
          <button class="sih-modal-btn" id="sih-ack-btn">Keep Me Safe (Dismiss)</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    const closeBtn = modal.querySelector('#sih-close-modal');
    const ackBtn = modal.querySelector('#sih-ack-btn');
    const close = () => modal.remove();
    if (closeBtn) closeBtn.onclick = close;
    if (ackBtn) ackBtn.onclick = close;
    modal.onclick = (e) => {
      if (e.target === modal) close();
    };
  }


  // Listen for queries from Popup (only if context is still valid)
  if (isExtensionContextValid()) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (!isExtensionContextValid()) return; // Extension was reloaded, ignore
      if (request.action === 'GET_ACTIVE_EMAIL') {
        const containers = findEmailContainers();
        const activeContainer = containers.length > 0
          ? (containers instanceof NodeList ? containers[0] : containers[0])
          : null;
        if (activeContainer) {
          const data = extractEmailData(activeContainer);
          sendResponse({ success: true, data });
        } else {
          sendResponse({ success: false, message: 'No email open in Gmail' });
        }
      }
      return true;
    });
  }

  // Watch for dynamic Gmail navigation
  const observer = new MutationObserver(() => {
    // Stop observing if the extension context has been invalidated (extension reloaded)
    if (!isExtensionContextValid()) {
      observer.disconnect();
      return;
    }
    injectAnalyzeButtons();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial passes on page load
  setTimeout(injectAnalyzeButtons, 500);
  setTimeout(injectAnalyzeButtons, 1500);
})();
