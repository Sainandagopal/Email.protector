import React, { useState } from 'react';
import { Upload, FileText, Zap, AlertCircle, CheckCircle, ArrowRight } from 'lucide-react';
import { analyzeEmail } from '../services/api';

const DEMO_PRESETS = {
  paypal: {
    title: "PayPal Urgent Phishing",
    desc: "Credential harvesting, IP URL & SPF failure",
    payload: {
      subject: "URGENT: Suspicious activity on your PayPal account - Action Required",
      sender: "PayPal Security Team <security-alert@paypa1-update-security.com>",
      date: new Date().toISOString(),
      body: "Dear Customer,\n\nWe detected unauthorized access to your account from IP address 185.220.101.5. To protect your funds, your account will be permanently suspended within 24 hours unless you verify your identity.\n\nClick the link below to confirm your password and card details immediately:\nhttp://185.220.101.5/login?ref=paypal_verify\n\nFailure to comply will result in account forfeiture.\n\nPayPal Identity Protection Department",
      headers: {
        "Received-SPF": "fail (domain does not designate 185.220.101.5 as permitted sender)",
        "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
        "Return-Path": "<bounce@attacker-bulletproof-host.ru>",
        "Received": "from mail.attacker-bulletproof-host.ru (185.220.101.5) by mx.google.com"
      },
      links: [
        { url: "http://185.220.101.5/login?ref=paypal_verify", text: "Verify Identity Immediately" }
      ]
    }
  },
  m365: {
    title: "Microsoft 365 Password Expiry BEC",
    desc: "Punycode domain & urgency social engineering",
    payload: {
      subject: "Security Notification: Password expiry scheduled in 2 hours",
      sender: "Microsoft IT Helpdesk <admin@xn--microsft-p2a.com>",
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
    }
  },
  benign: {
    title: "Authentic Cloud Billing Invoice (Safe)",
    desc: "Valid SPF/DKIM/DMARC, authentic Google relay",
    payload: {
      subject: "Your Monthly Cloud Infrastructure Invoice #INV-2026-09",
      sender: "Billing Department <billing@enterprise-cloud-services.com>",
      date: new Date().toISOString(),
      body: "Hi team,\n\nPlease find attached the summary for your monthly cloud infrastructure usage for the billing cycle ending September 2026. The balance has been auto-debited via your primary card on file.\n\nYou can review your detailed usage metrics in the official cloud dashboard:\nhttps://enterprise-cloud-services.com/dashboard/invoices\n\nThank you for choosing Enterprise Cloud Services.\nSupport Team",
      headers: {
        "Received-SPF": "pass (domain designates 142.250.190.46 as permitted sender)",
        "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        "Return-Path": "<billing@enterprise-cloud-services.com>",
        "Received": "from mail-relay.enterprise-cloud-services.com (142.250.190.46) by mx.google.com"
      },
      links: [
        { url: "https://enterprise-cloud-services.com/dashboard/invoices", text: "View Cloud Invoices" }
      ]
    }
  }
};

export default function AnalyzeEmail({ onAnalysisComplete }) {
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [rawText, setRawText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handlePreset = (key) => {
    const p = DEMO_PRESETS[key].payload;
    setSubject(p.subject);
    setSender(p.sender);
    setRawText(p.body);
    setError(null);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;
      setSubject(file.name);
      setSender("Uploaded .EML File");
      setRawText(content);
    };
    reader.readAsText(file);
  };

  const handleRunAnalysis = async () => {
    if (!rawText.trim() && !subject.trim()) {
      setError('Please provide email body text or select a preset.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const payload = {
        subject: subject || "Custom Ingested Email",
        sender: sender || "Anonymous / Manual Input",
        body: rawText,
        raw_eml: rawText.includes("From:") ? rawText : null
      };

      const result = await analyzeEmail(payload);
      onAnalysisComplete(result.id);
    } catch (err) {
      setError(err.message || 'Failed to submit email analysis.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 22, fontWeight: 800, color: '#fff' }}>Email Threat Ingestion Pipeline</h2>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
          Drop .EML files, paste raw RFC-822 message blocks, or load 1-click synthetic test presets
        </p>
      </div>

      {/* Preset Quick Loaders */}
      <div className="cyber-card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, fontSize: 13, fontWeight: 600, color: '#38bdf8' }}>
          <Zap size={16} /> Instant Hackathon Test Presets
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
          {Object.entries(DEMO_PRESETS).map(([key, item]) => (
            <button
              key={key}
              onClick={() => handlePreset(key)}
              style={{
                background: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid var(--border-cyan)',
                padding: '12px 14px',
                borderRadius: 8,
                textAlign: 'left',
                cursor: 'pointer',
                color: '#fff',
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => e.currentTarget.style.borderColor = '#38bdf8'}
              onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-cyan)'}
            >
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 2 }}>{item.title}</div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{item.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Upload & Form */}
      <div className="cyber-card">
        {/* Drop zone */}
        <label style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 24,
          border: '2px dashed rgba(56, 189, 248, 0.3)',
          borderRadius: 8,
          background: 'rgba(15, 23, 42, 0.5)',
          cursor: 'pointer',
          marginBottom: 18
        }}>
          <Upload size={28} color="#38bdf8" style={{ marginBottom: 8 }} />
          <span style={{ fontSize: 13, fontWeight: 600 }}>Click to select or drag &amp; drop .EML file</span>
          <span style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>Supports RFC-822, MIME messages with headers</span>
          <input type="file" accept=".eml,.txt" onChange={handleFileUpload} style={{ display: 'none' }} />
        </label>

        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '10px 14px',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--risk-critical)',
            borderRadius: 6,
            color: '#fca5a5',
            fontSize: 12,
            marginBottom: 16
          }}>
            <AlertCircle size={16} /> {error}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4, textTransform: 'uppercase' }}>Subject</label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g. Action Required: Account Notice"
              style={{
                width: '100%',
                padding: '9px 12px',
                background: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                color: '#fff',
                fontSize: 13
              }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4, textTransform: 'uppercase' }}>Sender</label>
            <input
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="e.g. Security Team <security@bank.com>"
              style={{
                width: '100%',
                padding: '9px 12px',
                background: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                color: '#fff',
                fontSize: 13
              }}
            />
          </div>
        </div>

        <div style={{ marginBottom: 18 }}>
          <label style={{ display: 'block', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4, textTransform: 'uppercase' }}>
            Email Body Content / Raw RFC-822 Text
          </label>
          <textarea
            rows={8}
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste raw email text, headers, and hyperlinks here..."
            style={{
              width: '100%',
              padding: 12,
              background: 'rgba(15, 23, 42, 0.8)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 6,
              color: '#fff',
              fontFamily: 'monospace',
              fontSize: 12,
              resize: 'vertical'
            }}
          />
        </div>

        <button
          className="btn btn-primary"
          style={{ width: '100%', padding: '12px 16px', fontSize: 14, justifyContent: 'center' }}
          onClick={handleRunAnalysis}
          disabled={loading}
        >
          {loading ? (
            <span>Evaluating NLP, Header Spoofing &amp; Infrastructure...</span>
          ) : (
            <>Execute Cyber-Forensic Analysis <ArrowRight size={16} /></>
          )}
        </button>
      </div>
    </div>
  );
}
