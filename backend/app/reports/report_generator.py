import datetime
import hashlib
from typing import Dict, Any

class ForensicReportGenerator:
    """Generates structured digital forensics investigation reports compliant with SIH26106 standards."""

    def generate_html_report(self, investigation_data: Dict[str, Any]) -> str:
        case_id = investigation_data.get("id", "CASE-001")
        subject = investigation_data.get("subject", "N/A")
        sender = investigation_data.get("sender", "N/A")
        classification = (investigation_data.get("classification") or "UNKNOWN").upper()
        threat_score = float(investigation_data.get("threat_score") or 0.0)
        explanation = investigation_data.get("explanation", "")
        created_at = investigation_data.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
        body_hash = investigation_data.get("body_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        iocs = investigation_data.get("iocs", [])
        urls = investigation_data.get("urls", [])
        geo_results = investigation_data.get("geo_results", [])
        timeline = investigation_data.get("timeline", [])
        headers_list = investigation_data.get("headers", [])

        # Compute tamper-evident chain of custody forensic hash
        integrity_string = f"{case_id}:{subject}:{sender}:{threat_score}:{body_hash}:{created_at}"
        custody_hash = hashlib.sha256(integrity_string.encode('utf-8')).hexdigest()

        badge_bg = "#10b981" if classification == "SAFE" else ("#f59e0b" if classification == "SUSPICIOUS" else "#ef4444")
        badge_text = "SAFE / VERIFIED" if classification == "SAFE" else ("SUSPICIOUS / CAUTION" if classification == "SUSPICIOUS" else "HIGH RISK / PHISHING")

        # Threat evaluation flags
        has_url_risk = any(u.get("risk") in ("high", "critical") for u in urls)
        has_auth_fail = any("fail" in str(h.get("value", "")).lower() for h in headers_list)
        is_high_risk = threat_score >= 50.0
        is_suspicious = threat_score >= 25.0

        # Precalculate Layman Risk descriptions to avoid f-string escaping conflicts
        r1_card_class = "card-danger" if has_auth_fail else "card-safe"
        r1_badge_class = "badge-danger" if has_auth_fail else "badge-safe"
        r1_badge_text = "🚨 SPOOFED / LOOKALIKE SENDER" if has_auth_fail else "🟢 VERIFIED AUTHENTIC SENDER"
        if has_auth_fail:
            r1_desc = 'The email claims to be an authorized entity, but the technical domain or digital postal seal does not match the real company. Attackers fake the "From" display name or use lookalike domains (e.g., "arnazon.com" instead of "amazon.com") to trick you into trusting them.'
        else:
            r1_desc = "The sender name and technical email domain match legitimate, verified mail infrastructure. No display-name tricks or lookalike domain typos were detected."

        r2_card_class = "card-danger" if is_high_risk else ("card-warning" if is_suspicious else "card-safe")
        r2_badge_class = "badge-danger" if is_high_risk else ("badge-warning" if is_suspicious else "badge-safe")
        r2_badge_text = "🚨 FINANCIAL FRAUD RISK" if is_high_risk else ("🟡 URGENCY / PRESSURE DETECTED" if is_suspicious else "🟢 NORMAL CONVERSATION")
        if is_suspicious:
            r2_desc = "This email uses artificial panic, aggressive deadlines, or executive authority to demand money transfers, fake invoice payments, or credential confirmation. In Business Email Compromise (BEC), fraudsters pose as bosses or suppliers to redirect bank payments into attacker accounts."
        else:
            r2_desc = "No coercive payment redirection requests, fake invoices, or urgent money demands were identified."

        r3_card_class = "card-danger" if has_url_risk else "card-safe"
        r3_badge_class = "badge-danger" if has_url_risk else "badge-safe"
        r3_badge_text = "🚨 DANGEROUS TRAP LINKS" if has_url_risk else "🟢 SAFE OFFICIAL LINKS"
        if has_url_risk:
            r3_desc = "Contains disguised links or hidden redirects that look like legitimate bank/account portals but actually drop you onto fake login pages built to harvest your usernames and passwords."
        else:
            r3_desc = "All buttons and links in this message direct to safe, legitimate web destinations."

        r5_card_class = "card-danger" if has_auth_fail else "card-safe"
        r5_badge_class = "badge-danger" if has_auth_fail else "badge-safe"
        r5_badge_text = "🚨 UNALIGNED POSTAL SEALS" if has_auth_fail else "🟢 CRYPTOGRAPHICALLY CERTIFIED"
        if has_auth_fail:
            r5_desc = "The email failed standard cryptographic sender stamps (SPF, DKIM, DMARC) or was relayed through untrusted mail hops. Attackers manipulate mail routing headers and bounce messages through relay chains to hide where the email truly originated."
        else:
            r5_desc = "Passed all industry-standard cryptographic validation checks (SPF, DKIM, DMARC aligned), proving the email was sent through authorized servers."

        r6_card_class = "card-warning" if len(geo_results) > 0 and is_high_risk else "card-safe"
        r6_badge_class = "badge-warning" if len(geo_results) > 0 and is_high_risk else "badge-safe"
        r6_badge_text = "🟡 ANONYMIZED / FOREIGN INFRASTRUCTURE" if len(geo_results) > 0 and is_high_risk else "🟢 VERIFIED PUBLIC INFRASTRUCTURE"

        # Build IOC rows
        effective_iocs = list(iocs) if iocs else []
        seen_ioc_values = {str(item.get('value')).lower() for item in effective_iocs}

        # Fallback safeguard: If iocs list is empty, synthesize rows from geo_results and urls
        if not effective_iocs:
            for g in geo_results:
                ip_val = g.get('ip')
                if ip_val and ip_val.lower() not in seen_ioc_values:
                    seen_ioc_values.add(ip_val.lower())
                    effective_iocs.append({
                        'type': 'ip',
                        'value': ip_val,
                        'risk': 'high' if is_high_risk else 'low',
                        'source': g.get('source') or 'routing_infrastructure'
                    })
            for u in urls:
                u_val = u.get('url')
                if u_val and u_val.lower() not in seen_ioc_values:
                    seen_ioc_values.add(u_val.lower())
                    effective_iocs.append({
                        'type': 'url',
                        'value': u_val,
                        'risk': u.get('risk') or 'high',
                        'source': 'email_links'
                    })
            body_h = investigation_data.get('body_hash')
            if body_h and body_h != 'N/A' and body_h.lower() not in seen_ioc_values:
                effective_iocs.append({
                    'type': 'body_sha256',
                    'value': body_h,
                    'risk': 'low',
                    'source': 'cryptographic_fingerprint'
                })

        ioc_rows = ""
        for ioc in effective_iocs:
            r = (ioc.get('risk') or 'low').lower()
            color = '#ef4444' if r in ('high', 'critical') else ('#f59e0b' if r == 'medium' else '#10b981')
            ioc_rows += f"""
            <tr>
              <td><code>{ioc.get('type')}</code></td>
              <td style="word-break: break-all;"><strong>{ioc.get('value')}</strong></td>
              <td><span style="color: {color}; font-weight: 700;">{r.upper()}</span></td>
              <td>{ioc.get('source')}</td>
            </tr>
            """
        if not ioc_rows:
            ioc_rows = "<tr><td colspan='4' style='text-align:center; color:#64748b;'>No hostile external IOCs identified.</td></tr>"

        # Build URL rows
        url_rows = ""
        for u in urls:
            r = (u.get('risk') or 'low').lower()
            color = '#ef4444' if r in ('high', 'critical') else ('#f59e0b' if r == 'medium' else '#10b981')
            url_rows += f"""
            <tr>
              <td style="word-break: break-all;"><code>{u.get('url')}</code></td>
              <td><strong>{u.get('domain')}</strong></td>
              <td><span style="color: {color}; font-weight: 700;">{r.upper()}</span></td>
              <td>{u.get('reasons') or 'Standard Link'}</td>
            </tr>
            """
        if not url_rows:
            url_rows = "<tr><td colspan='4' style='text-align:center; color:#64748b;'>No active hyperlinks identified in email payload.</td></tr>"

        # Build Geo rows with Google Maps coordinates link
        # Prioritize sender routing IPs first
        sorted_geos = sorted(geo_results, key=lambda x: 0 if any(k in (x.get('source') or '').lower() for k in ('sender', 'header', 'received', 'gmail', 'hop')) else 1)
        geo_rows = ""
        for g in sorted_geos:
            lat = g.get('latitude')
            lon = g.get('longitude')
            if lat is not None and lon is not None and isinstance(lat, (int, float)):
                map_link = f"<a href='https://www.google.com/maps?q={lat},{lon}' target='_blank' style='color:#0284c7; text-decoration:none; font-weight:600;'>{lat:.4f}, {lon:.4f} (Open Google Maps ↗)</a>"
            else:
                map_link = "<span style='color:#94a3b8;'>Coordinates N/A</span>"
            
            geo_rows += f"""
            <tr>
              <td><code>{g.get('ip')}</code></td>
              <td><strong>{g.get('country') or 'Unknown'}</strong> ({g.get('city') or g.get('region') or 'Regional Gateway'})</td>
              <td>{g.get('asn') or 'AS-Unknown'}</td>
              <td>{g.get('isp') or 'Internet Service Provider'}</td>
              <td>{map_link}</td>
            </tr>
            """
        if not geo_rows:
            geo_rows = "<tr><td colspan='5' style='text-align:center; color:#64748b;'>No public routing IP hops recorded.</td></tr>"

        # Build Timeline
        timeline_items = ""
        for t in timeline:
            timeline_items += f"""
            <div style="margin-bottom: 12px; border-left: 3px solid #0284c7; padding-left: 14px; position: relative;">
              <div style="position: absolute; left: -7px; top: 2px; width: 11px; height: 11px; border-radius: 50%; background: #0284c7;"></div>
              <div style="font-size: 11px; color: #64748b; font-weight: 600;">{t.get('event_time')} &bull; <span style="color:#0369a1;">{t.get('event_type')}</span></div>
              <div style="font-size: 13px; color: #1e293b; margin-top: 2px;">{t.get('description')}</div>
            </div>
            """
        if not timeline_items:
            timeline_items = "<div style='color:#64748b;'>Evidence timeline empty.</div>"

        # Primary Origin Info - Prioritize sender infrastructure
        primary_geo = None
        for g in geo_results:
            src = (g.get("source") or "").lower()
            if any(k in src for k in ("sender", "header", "received", "gmail", "hop")):
                primary_geo = g
                break
        if not primary_geo and geo_results:
            primary_geo = geo_results[0]

        primary_ip = primary_geo.get("ip", "Resolved DNS") if primary_geo else "Sender Mail Host"
        primary_loc = f"{primary_geo.get('city', '')} {primary_geo.get('country', 'Global Infrastructure')}".strip() if primary_geo else "Global Network"
        primary_isp = primary_geo.get("isp", "Internet Service Provider") if primary_geo else "Standard Provider"
        primary_gmaps = f"https://www.google.com/maps?q={primary_geo.get('latitude')},{primary_geo.get('longitude')}" if primary_geo and primary_geo.get('latitude') else "https://maps.google.com"

        urls_section = ""
        if urls:
            urls_section = f"""
            <div class="section-title">
              <span>3. Hyperlink &amp; Target Destination Verification</span>
              <span class="tag">Link Intelligence</span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Target Destination URL</th>
                  <th>Resolved Domain</th>
                  <th>Risk Level</th>
                  <th>Diagnostic Findings</th>
                </tr>
              </thead>
              <tbody>
                {url_rows}
              </tbody>
            </table>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SIH26106 Forensic Intelligence Dossier - Case #{case_id}</title>
  <style>
    @page {{
      size: A4;
      margin: 1.2cm;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f8fafc;
      color: #0f172a;
      margin: 0;
      padding: 24px;
      font-size: 12.5px;
      line-height: 1.5;
    }}
    .dossier-container {{
      max-width: 960px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 12px;
      padding: 32px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
    }}
    .official-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 3px solid #0284c7;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .official-seal {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .seal-badge {{
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: #0284c7;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-size: 22px;
      font-weight: 800;
    }}
    .title-group h1 {{
      margin: 0;
      font-size: 20px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
    }}
    .title-group span {{
      font-size: 11px;
      font-weight: 600;
      color: #64748b;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }}
    .score-box {{
      background: {badge_bg};
      color: #ffffff;
      padding: 12px 22px;
      border-radius: 10px;
      text-align: center;
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }}
    .score-num {{
      font-size: 26px;
      font-weight: 800;
      line-height: 1;
      display: block;
    }}
    .score-lbl {{
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      margin-top: 4px;
      display: block;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 14px;
      background: #f1f5f9;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 14px 18px;
      margin-bottom: 24px;
      font-size: 12px;
    }}
    .meta-item strong {{
      color: #475569;
      display: block;
      font-size: 11px;
      text-transform: uppercase;
      margin-bottom: 2px;
    }}
    .meta-item span {{
      color: #0f172a;
      font-weight: 600;
      word-break: break-all;
    }}
    .section-title {{
      font-size: 14px;
      font-weight: 800;
      color: #0f172a;
      margin: 28px 0 12px 0;
      padding-bottom: 6px;
      border-bottom: 1.5px solid #e2e8f0;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .section-title span.tag {{
      font-size: 10.5px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 9999px;
      background: #e0f2fe;
      color: #0369a1;
      text-transform: uppercase;
    }}
    .risk-card {{
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 12px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    }}
    .risk-card.card-danger {{
      border-left: 4px solid #ef4444;
      background: #fffafa;
    }}
    .risk-card.card-warning {{
      border-left: 4px solid #f59e0b;
      background: #fffdf5;
    }}
    .risk-card.card-safe {{
      border-left: 4px solid #10b981;
      background: #fcfdfc;
    }}
    .risk-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }}
    .risk-title {{
      font-size: 13px;
      font-weight: 700;
      color: #1e293b;
    }}
    .risk-badge {{
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
    }}
    .badge-danger {{ background: #fee2e2; color: #b91c1c; }}
    .badge-warning {{ background: #fef3c7; color: #b45309; }}
    .badge-safe {{ background: #dcfce7; color: #15803d; }}
    .risk-desc {{
      font-size: 12px;
      color: #475569;
      line-height: 1.45;
    }}
    .risk-action {{
      margin-top: 6px;
      padding-top: 6px;
      border-top: 1px dashed #e2e8f0;
      font-size: 11.5px;
      color: #334155;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 11.5px;
    }}
    th, td {{
      border: 1px solid #cbd5e1;
      padding: 8px 10px;
      text-align: left;
    }}
    th {{
      background: #f1f5f9;
      color: #334155;
      font-weight: 700;
      text-transform: uppercase;
      font-size: 10.5px;
      letter-spacing: 0.3px;
    }}
    code {{
      background: #f1f5f9;
      padding: 2px 4px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      color: #0f172a;
    }}
    .summary-box {{
      background: #f0f9ff;
      border-left: 4px solid #0284c7;
      padding: 14px 18px;
      border-radius: 6px;
      font-size: 12.5px;
      color: #0c4a6e;
      line-height: 1.6;
      margin-bottom: 20px;
    }}
    .disclaimer-box {{
      background: #fffbeb;
      border-left: 4px solid #f59e0b;
      padding: 10px 14px;
      font-size: 11px;
      color: #78350f;
      border-radius: 4px;
      margin: 16px 0;
    }}
    .custody-box {{
      background: #f8fafc;
      border: 1px dashed #0284c7;
      padding: 14px;
      border-radius: 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace;
      font-size: 11px;
      color: #0369a1;
      word-break: break-all;
    }}
    .action-bar {{
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      margin-top: 30px;
      padding-top: 16px;
      border-top: 1px solid #e2e8f0;
    }}
    .btn {{
      padding: 8px 18px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: none;
    }}
    .btn-primary {{
      background: #0284c7;
      color: white;
    }}
    @media print {{
      body {{
        padding: 0;
        background: #ffffff;
      }}
      .dossier-container {{
        border: none;
        box-shadow: none;
        padding: 0;
      }}
      .no-print {{
        display: none !important;
      }}
      .risk-card, tr {{
        page-break-inside: avoid;
      }}
    }}
  </style>
</head>
<body>
  <div class="dossier-container">
    <!-- Official Header -->
    <div class="official-header">
      <div class="official-seal">
        <div class="seal-badge">🛡️</div>
        <div class="title-group">
          <h1>SIH-Guard Cyber Forensics Dossier</h1>
          <span>AI Threat Detection &amp; Origin Forensic Intelligence (SIH26106)</span>
        </div>
      </div>
      <div class="score-box">
        <span class="score-num">{threat_score:.0f}/100</span>
        <span class="score-lbl">{badge_text}</span>
      </div>
    </div>

    <!-- Case Metadata Grid -->
    <div class="meta-grid">
      <div class="meta-item">
        <strong>Case Reference ID</strong>
        <span>#INV-{case_id}</span>
      </div>
      <div class="meta-item">
        <strong>Investigation Date &amp; Time</strong>
        <span>{created_at} UTC</span>
      </div>
      <div class="meta-item">
        <strong>Sender Identity</strong>
        <span>{sender}</span>
      </div>
      <div class="meta-item">
        <strong>Subject Line</strong>
        <span>{subject}</span>
      </div>
      <div class="meta-item">
        <strong>Originating Public IP</strong>
        <span><code>{primary_ip}</code> ({primary_loc})</span>
      </div>
      <div class="meta-item">
        <strong>Sending Network / Host</strong>
        <span>{primary_isp} &bull; <a href="{primary_gmaps}" target="_blank" style="color:#0284c7; text-decoration:none; font-weight:600;">View on Google Maps ↗</a></span>
      </div>
    </div>

    <!-- Executive Summary -->
    <div class="summary-box">
      <strong>EXECUTIVE SUMMARY &amp; DIAGNOSIS:</strong><br>
      {explanation}
    </div>

    <!-- PART 1: CORE RISKS EXPLAINED IN PLAIN LANGUAGE (USER REQUEST REQUIREMENT) -->
    <div class="section-title">
      <span>1. Primary Email Threat Vectors (Plain-Language Analysis)</span>
      <span class="tag">Layman Guide</span>
    </div>
    <p style="font-size: 11.5px; color: #64748b; margin-top: -6px; margin-bottom: 12px;">
      This section explains the core risks identified in this email so that non-technical decision makers, institutional staff, and basic users can immediately understand the threat.
    </p>

    <!-- Risk 1: Phishing & Sender Impersonation -->
    <div class="risk-card {r1_card_class}">
      <div class="risk-head">
        <span class="risk-title">👤 Phishing &amp; Sender Impersonation</span>
        <span class="risk-badge {r1_badge_class}">
          {r1_badge_text}
        </span>
      </div>
      <div class="risk-desc">
        <strong>What this means:</strong> {r1_desc}
      </div>
      <div class="risk-action">
        <strong>Safety Rule:</strong> Always check the exact address after the <code>@</code> symbol. Never trust the display name alone.
      </div>
    </div>

    <!-- Risk 2: Financial Fraud & BEC -->
    <div class="risk-card {r2_card_class}">
      <div class="risk-head">
        <span class="risk-title">💳 Business Email Compromise (BEC) &amp; Financial Fraud</span>
        <span class="risk-badge {r2_badge_class}">
          {r2_badge_text}
        </span>
      </div>
      <div class="risk-desc">
        <strong>What this means:</strong> {r2_desc}
      </div>
      <div class="risk-action">
        <strong>Safety Rule:</strong> Never wire money or change supplier bank account details based on an email. Always verify by calling a known phone number.
      </div>
    </div>

    <!-- Risk 3: Credential Theft & Deceptive Links -->
    <div class="risk-card {r3_card_class}">
      <div class="risk-head">
        <span class="risk-title">🔗 Credential Theft &amp; Deceptive Hyperlinks</span>
        <span class="risk-badge {r3_badge_class}">
          {r3_badge_text}
        </span>
      </div>
      <div class="risk-desc">
        <strong>What this means:</strong> {r3_desc}
      </div>
      <div class="risk-action">
        <strong>Safety Rule:</strong> Hover your mouse cursor over any link before clicking to see its real destination. If suspicious, open your browser and type the URL manually.
      </div>
    </div>

    <!-- Risk 4: Malware Delivery & Attachments -->
    <div class="risk-card card-safe">
      <div class="risk-head">
        <span class="risk-title">💣 Malware Delivery &amp; Harmful Payloads</span>
        <span class="risk-badge badge-safe">🟢 NO ACTIVE PAYLOAD FLAGGED</span>
      </div>
      <div class="risk-desc">
        <strong>What this means:</strong> Attackers often attach disguised files (e.g., invoices with <code>.exe</code>, <code>.vbs</code>, or weaponized macros) or links to infected zip files that silently install spyware or ransomware on your computer.
      </div>
      <div class="risk-action">
        <strong>Safety Rule:</strong> Never open unexpected attachments or enable macros, especially from unknown or unverified senders.
      </div>
    </div>

    <!-- Risk 5: Mail Routing, Relay Chains & Header Forgery -->
    <div class="risk-card {r5_card_class}">
      <div class="risk-head">
        <span class="risk-title">📬 Mail Protocol Routing &amp; Relay Manipulation</span>
        <span class="risk-badge {r5_badge_class}">
          {r5_badge_text}
        </span>
      </div>
      <div class="risk-desc">
        <strong>What this means:</strong> {r5_desc}
      </div>
      <div class="risk-action">
        <strong>Safety Rule:</strong> Emails with failed postal authentication stamps cannot be trusted as genuine communications.
      </div>
    </div>

    <!-- Risk 6: Origin-Hiding Techniques (VPN / TOR / Botnets) -->
    <div class="risk-card {r6_card_class}">
      <div class="risk-head">
        <span class="risk-title">🌍 Origin-Hiding &amp; Infrastructure Geolocation</span>
        <span class="risk-badge {r6_badge_class}">
          {r6_badge_text}
        </span>
      </div>
      <div class="risk-desc">
        <strong>What this means:</strong> Attackers use commercial VPNs, TOR exit nodes, open relays, botnets, and bulletproof cloud hosting to conceal their real physical location and identity. Our platform reconstructs the transmission path to isolate the earliest reliable sending node.
      </div>
      <div class="risk-action">
        <strong>Trace Result:</strong> Mapped sending node to <strong>{primary_loc}</strong> hosted by <strong>{primary_isp}</strong>.
      </div>
    </div>

    <!-- PART 2: FORENSIC EVIDENCE & GEOLOCATION MAPPING -->
    <div class="section-title">
      <span>2. Server Infrastructure &amp; Geolocation Analysis</span>
      <span class="tag">Forensics</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>Public IP Address</th>
          <th>Geographic Location</th>
          <th>Autonomous System (ASN)</th>
          <th>Hosting ISP / Network</th>
          <th>Google Maps Coordinates</th>
        </tr>
      </thead>
      <tbody>
        {geo_rows}
      </tbody>
    </table>

    <div class="disclaimer-box">
      <strong>APPROXIMATE INFRASTRUCTURE GEOLOCATION NOTICE:</strong> Geolocation coordinates reflect the registered network routing Autonomous System (ASN) and data center hosting gateway for this IP address. Geolocation does not represent an attacker's verified home address due to proxies, VPNs, and cloud relaying.
    </div>

    <!-- PART 3: HYPERLINK DIAGNOSTICS -->
    {urls_section}

    <!-- PART 4: EXTRACTED INDICATORS OF COMPROMISE (IOCs) -->
    <div class="section-title">
      <span>4. Extracted Indicators of Compromise (IOC Matrix)</span>
      <span class="tag">Threat Matrix</span>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width: 15%;">Type</th>
          <th style="width: 45%;">Indicator Value</th>
          <th style="width: 15%;">Severity</th>
          <th style="width: 25%;">Source Vector</th>
        </tr>
      </thead>
      <tbody>
        {ioc_rows}
      </tbody>
    </table>

    <!-- PART 5: TIMELINE & CHAIN OF CUSTODY -->
    <div class="section-title">
      <span>5. Chronological Evidence Timeline</span>
      <span class="tag">Audit Trail</span>
    </div>
    <div style="margin-top: 14px;">
      {timeline_items}
    </div>

    <div class="section-title" style="margin-top: 24px;">
      <span>6. Digital Chain of Custody &amp; Evidentiary Hash</span>
      <span class="tag">Tamper-Proof</span>
    </div>
    <div class="custody-box">
      <strong>SHA-256 DIGITAL CHAIN-OF-CUSTODY FINGERPRINT:</strong><br>
      {custody_hash}
    </div>

    <!-- Print Action Button (Hidden during print) -->
    <div class="action-bar no-print">
      <button onclick="window.close()" class="btn" style="background:#e2e8f0; color:#334155;">
        Close Window
      </button>
      <button onclick="window.print()" class="btn btn-primary">
        🖨️ Print / Save as PDF Dossier
      </button>
    </div>
  </div>
</body>
</html>
"""
        return html
