import React, { useEffect, useState } from 'react';
import { 
  Shield, AlertTriangle, Globe, Link, Clock, Network, 
  FileText, Copy, Check, ArrowLeft, ExternalLink, Download, Search, Filter 
} from 'lucide-react';
import { getInvestigationDetail, getInvestigationGraph, generateReport } from '../services/api';
import MapViewer from '../components/MapViewer';
import AttackGraph from '../components/AttackGraph';

export default function InvestigationDetail({ investigationId, onBack }) {
  const [detail, setDetail] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [activeTab, setActiveTab] = useState('summary');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // IOC Filter state
  const [iocFilter, setIocFilter] = useState('all');
  const [iocSearch, setIocSearch] = useState('');
  const [copiedVal, setCopiedVal] = useState(null);

  // Report state
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportUrl, setReportUrl] = useState(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [det, gr] = await Promise.all([
          getInvestigationDetail(investigationId),
          getInvestigationGraph(investigationId)
        ]);
        setDetail(det);
        setGraphData(gr);
      } catch (err) {
        setError(err.message || 'Failed to load dossier');
      } finally {
        setLoading(false);
      }
    }
    if (investigationId) {
      loadData();
    }
  }, [investigationId]);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedVal(text);
    setTimeout(() => setCopiedVal(null), 2000);
  };

  const handleCreateReport = async () => {
    setGeneratingReport(true);
    try {
      const res = await generateReport(investigationId);
      setReportUrl(`http://localhost:8000${res.report_url}`);
    } catch (err) {
      alert('Report generation failed: ' + err.message);
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>Decrypting &amp; analyzing forensic dossier...</div>;
  }

  if (error || !detail) {
    return (
      <div className="cyber-card" style={{ textAlign: 'center', padding: 40 }}>
        <AlertTriangle size={36} color="#ef4444" style={{ marginBottom: 12 }} />
        <h3 style={{ color: '#fff' }}>Dossier Load Error</h3>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 16 }}>{error || 'Investigation record not found'}</p>
        <button className="btn btn-secondary" onClick={onBack}><ArrowLeft size={14} /> Back to Overview</button>
      </div>
    );
  }

  const score = Math.round(detail.threat_score || 0);
  const cls = (detail.classification || 'UNKNOWN').toLowerCase();

  // Filter IOCs
  const filteredIocs = detail.iocs.filter(ioc => {
    const matchesType = iocFilter === 'all' || ioc.type.toLowerCase().includes(iocFilter);
    const matchesSearch = ioc.value.toLowerCase().includes(iocSearch.toLowerCase()) || ioc.source.toLowerCase().includes(iocSearch.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div>
      {/* Back Button & Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <button className="btn btn-secondary" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Hub
        </button>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-primary" onClick={handleCreateReport} disabled={generatingReport}>
            <FileText size={14} /> {generatingReport ? 'Generating...' : 'Export Forensic Report'}
          </button>
          <a
            href={`http://localhost:8000/api/v1/reports/${detail.id}/html`}
            target="_blank"
            rel="noreferrer"
            className="btn btn-secondary"
          >
            <ExternalLink size={14} /> View Printable HTML
          </a>
        </div>
      </div>

      {/* Dossier Banner Header */}
      <div className="cyber-card" style={{ marginBottom: 20, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <span style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--accent-cyan)' }}>#CASE-INV-{detail.id}</span>
            <span className={`badge badge-${cls}`}>{detail.classification}</span>
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{new Date(detail.created_at).toLocaleString()}</span>
          </div>
          <h2 style={{ fontSize: 20, fontWeight: 800, color: '#fff', marginBottom: 4 }}>{detail.subject}</h2>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            <strong>Sender Origin:</strong> {detail.sender}
          </div>
        </div>

        {/* Threat Score Circle */}
        <div style={{
          width: 96,
          height: 96,
          borderRadius: '50%',
          border: `4px solid ${score >= 50 ? 'var(--risk-critical)' : (score >= 25 ? 'var(--risk-suspicious)' : 'var(--risk-safe)')}`,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: `0 0 24px ${score >= 50 ? 'rgba(239, 68, 68, 0.45)' : 'rgba(16, 185, 129, 0.35)'}`,
          background: 'rgba(15, 23, 42, 0.85)',
          flexShrink: 0
        }}>
          <span style={{ fontSize: 30, fontWeight: 900, color: '#fff', lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginTop: 2 }}>/ 100 RISK</span>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 6, borderBottom: '1px solid var(--border-subtle)', marginBottom: 20 }}>
        {[
          { id: 'summary', label: 'Executive Dossier', icon: Shield },
          { id: 'iocs', label: `IOC Matrix (${detail.iocs.length})`, icon: Link },
          { id: 'geo', label: `Infrastructure Geo (${detail.geo_results.length})`, icon: Globe },
          { id: 'timeline', label: `Evidence Timeline (${detail.timeline.length})`, icon: Clock },
          { id: 'graph', label: 'Visual Attack Graph', icon: Network },
          { id: 'report', label: 'Forensic Report', icon: FileText }
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 16px',
                background: isActive ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                color: isActive ? '#fff' : 'var(--text-secondary)',
                fontWeight: 600,
                fontSize: 13,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              <Icon size={14} color={isActive ? 'var(--accent-cyan)' : 'var(--text-tertiary)'} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT: Summary */}
      {activeTab === 'summary' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* AI Explanation */}
          <div className="cyber-card" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: 8 }}>
              AI Threat Reasoning &amp; Evidence Correlation
            </h3>
            <p style={{ fontSize: 13, lineHeight: 1.6, color: '#e2e8f0' }}>
              {detail.explanation}
            </p>
          </div>

          {/* Authentication & Spoofing Indicators */}
          <div className="cyber-card">
            <h3 style={{ fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 16 }}>
              Authentication &amp; Envelope Spoofing Verification
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>SPF Validation</span>
                <div style={{ fontSize: 14, fontWeight: 700, marginTop: 4, color: detail.headers.some(h => h.value.includes('spf=fail') || h.name.includes('spf') && h.value.includes('fail')) ? 'var(--risk-critical)' : 'var(--risk-safe)' }}>
                  {detail.headers.some(h => h.value.includes('spf=fail') || h.name.includes('spf') && h.value.includes('fail')) ? 'FAIL (Unverified IP)' : 'PASS / ALIGNED'}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>DKIM Cryptographic Sign</span>
                <div style={{ fontSize: 14, fontWeight: 700, marginTop: 4, color: detail.headers.some(h => h.value.includes('dkim=fail')) ? 'var(--risk-critical)' : 'var(--risk-safe)' }}>
                  {detail.headers.some(h => h.value.includes('dkim=fail')) ? 'FAIL / CORRUPTED' : 'VERIFIED / PRESENT'}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>DMARC Policy Compliance</span>
                <div style={{ fontSize: 14, fontWeight: 700, marginTop: 4, color: detail.headers.some(h => h.value.includes('dmarc=fail')) ? 'var(--risk-critical)' : 'var(--risk-safe)' }}>
                  {detail.headers.some(h => h.value.includes('dmarc=fail')) ? 'REJECT / QUARANTINE' : 'PASS'}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Body Integrity Fingerprint</span>
                <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent-cyan)', marginTop: 6, wordBreak: 'break-all' }}>
                  {detail.body_hash ? `${detail.body_hash.substring(0, 24)}...` : 'N/A'}
                </div>
              </div>
            </div>
          </div>

          {/* Hyperlinks Analysis Highlights */}
          {detail.urls.length > 0 && (
            <div className="cyber-card">
              <h3 style={{ fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 12 }}>
                Analyzed Target Hyperlinks ({detail.urls.length})
              </h3>
              <div style={{ overflowX: 'auto' }}>
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Target Link Destination</th>
                      <th>Resolved Host</th>
                      <th>Risk</th>
                      <th>Diagnostic Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.urls.map(u => (
                      <tr key={u.id || u.url}>
                        <td style={{ maxWidth: 300, wordBreak: 'break-all' }}><code>{u.url}</code></td>
                        <td>{u.domain}</td>
                        <td><span className={`badge badge-${u.risk}`}>{u.risk}</span></td>
                        <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{u.reasons}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB CONTENT: IOC Matrix */}
      {activeTab === 'iocs' && (
        <div className="cyber-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, gap: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 8 }}>
              {['all', 'ip', 'domain', 'url', 'hash', 'email'].map(type => (
                <button
                  key={type}
                  className={`btn ${iocFilter === type ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: 11, textTransform: 'uppercase' }}
                  onClick={() => setIocFilter(type)}
                >
                  {type}
                </button>
              ))}
            </div>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-tertiary)' }} />
              <input
                type="text"
                placeholder="Search IOCs..."
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
                style={{
                  padding: '7px 12px 7px 32px',
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  color: '#fff',
                  fontSize: 12,
                  width: 220
                }}
              />
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator Value</th>
                  <th>Severity</th>
                  <th>Vector Source</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredIocs.map((ioc, idx) => (
                  <tr key={ioc.id || idx}>
                    <td><code>{ioc.type}</code></td>
                    <td style={{ fontWeight: 600, color: '#fff', wordBreak: 'break-all' }}>{ioc.value}</td>
                    <td>
                      <span className={`badge badge-${ioc.risk === 'critical' || ioc.risk === 'high' ? 'phishing' : (ioc.risk === 'medium' ? 'suspicious' : 'safe')}`}>
                        {ioc.risk}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>{ioc.source}</td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '4px 8px', fontSize: 11 }}
                        onClick={() => handleCopy(ioc.value)}
                      >
                        {copiedVal === ioc.value ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT: GeoLocation & Infrastructure */}
      {activeTab === 'geo' && (
        <div className="cyber-card">
          <h3 style={{ fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 12 }}>
            Public Mail Routing Infrastructure Mapping
          </h3>
          <MapViewer geoResults={detail.geo_results} />

          <h4 style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginTop: 24, marginBottom: 12 }}>
            Mapped Hop Servers &amp; Autonomous Systems
          </h4>
          <div style={{ overflowX: 'auto' }}>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Public IP</th>
                  <th>Geographic Location</th>
                  <th>Autonomous System (ASN)</th>
                  <th>Hosting ISP / Organization</th>
                  <th>Coordinates</th>
                </tr>
              </thead>
              <tbody>
                {detail.geo_results.map((g, idx) => (
                  <tr key={g.id || idx}>
                    <td><code>{g.ip}</code></td>
                    <td>{g.country} ({g.city || g.region || 'Public Node'})</td>
                    <td>{g.asn || 'AS-N/A'}</td>
                    <td>{g.isp || 'N/A'}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11 }}>
                      {g.latitude?.toFixed(4)}, {g.longitude?.toFixed(4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Timeline */}
      {activeTab === 'timeline' && (
        <div className="cyber-card">
          <h3 style={{ fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 16 }}>
            Chronological Forensic Evidence Timeline
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, borderLeft: '2px solid var(--accent-cyan)', paddingLeft: 20, marginLeft: 10 }}>
            {detail.timeline.map((ev, idx) => (
              <div key={ev.id || idx} style={{ position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  left: -27,
                  top: 2,
                  width: 12,
                  height: 12,
                  borderRadius: '50%',
                  background: 'var(--accent-cyan)',
                  boxShadow: '0 0 8px var(--accent-cyan)'
                }} />
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginBottom: 2 }}>
                  {new Date(ev.event_time).toLocaleTimeString()} &bull; <strong style={{ color: 'var(--accent-cyan)' }}>{ev.event_type}</strong>
                </div>
                <div style={{ fontSize: 13, color: '#e2e8f0', background: 'rgba(15, 23, 42, 0.6)', padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                  {ev.description}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB CONTENT: Attack Graph */}
      {activeTab === 'graph' && (
        <div className="cyber-card">
          <h3 style={{ fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 8 }}>
            Visual Attack Vector Graph
          </h3>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
            Interactive node-link relationship diagram connecting Sender origin, Mail relay IPs, and target destination URLs. Click any node to inspect telemetry.
          </p>
          <AttackGraph graphData={graphData} />
        </div>
      )}

      {/* TAB CONTENT: Forensic Report */}
      {activeTab === 'report' && (
        <div className="cyber-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: '#fff' }}>Official Forensic Investigation Report</h3>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Certified digital audit report with SHA-256 chain-of-custody fingerprint
              </p>
            </div>
            <a
              href={`http://localhost:8000/api/v1/reports/${detail.id}/html`}
              target="_blank"
              rel="noreferrer"
              className="btn btn-primary"
            >
              <Download size={14} /> Open Printable Dossier
            </a>
          </div>

          <iframe
            src={`http://localhost:8000/api/v1/reports/${detail.id}/html`}
            title="Forensic Report Preview"
            style={{
              width: '100%',
              height: 600,
              borderRadius: 8,
              border: '1px solid var(--border-cyan)',
              background: '#fff'
            }}
          />
        </div>
      )}
    </div>
  );
}
