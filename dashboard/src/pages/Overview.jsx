import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle2, AlertCircle, ArrowRight, RefreshCw, PlusCircle, Search } from 'lucide-react';
import { getInvestigations } from '../services/api';

export default function Overview({ onSelectInvestigation, onNavigateToAnalyze }) {
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await getInvestigations();
      setInvestigations(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const total = investigations.length;
  const highRiskCount = investigations.filter(i => i.threat_score >= 50).length;
  const safeCount = investigations.filter(i => i.threat_score < 25).length;
  const suspCount = investigations.filter(i => i.threat_score >= 25 && i.threat_score < 50).length;

  const safePct = total > 0 ? Math.round((safeCount / total) * 100) : 0;
  const suspPct = total > 0 ? Math.round((suspCount / total) * 100) : 0;
  const highPct = total > 0 ? Math.round((highRiskCount / total) * 100) : 0;

  const filtered = investigations.filter(inv => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      (inv.subject && inv.subject.toLowerCase().includes(term)) ||
      (inv.sender && inv.sender.toLowerCase().includes(term)) ||
      (inv.classification && inv.classification.toLowerCase().includes(term)) ||
      `#inv-${inv.id}`.includes(term)
    );
  });

  return (
    <div>
      {/* Top Banner Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexWrap: 'wrap', gap: 14 }}>
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>Threat Monitoring Overview</h2>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2 }}>
            Real-time feed of scanned mailbox traffic, threat classifications, and forensic analysis.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary" onClick={loadData}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Feed
          </button>
          <button className="btn btn-primary" onClick={onNavigateToAnalyze}>
            <PlusCircle size={14} /> Analyze New Message
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-icon-wrap" style={{ background: 'rgba(59, 130, 246, 0.1)', color: '#60a5fa' }}>
            <Shield size={22} />
          </div>
          <div>
            <div className="kpi-val">{total}</div>
            <div className="kpi-label">Total Messages Scanned</div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap" style={{ background: 'rgba(244, 63, 94, 0.1)', color: '#fb7185' }}>
            <AlertTriangle size={22} />
          </div>
          <div>
            <div className="kpi-val" style={{ color: '#fb7185' }}>{highRiskCount}</div>
            <div className="kpi-label">Malicious / Phishing</div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap" style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24' }}>
            <AlertCircle size={22} />
          </div>
          <div>
            <div className="kpi-val" style={{ color: '#fbbf24' }}>{suspCount}</div>
            <div className="kpi-label">Suspicious / Flagged</div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#34d399' }}>
            <CheckCircle2 size={22} />
          </div>
          <div>
            <div className="kpi-val" style={{ color: '#34d399' }}>{safeCount}</div>
            <div className="kpi-label">Clean &amp; Authentic</div>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="cyber-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff' }}>Recent Scans &amp; Investigations</h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Click any investigation to review the authentication signals, IOCs, and origin map.
            </p>
          </div>

          <div style={{ position: 'relative', width: 240 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-tertiary)' }} />
            <input
              type="text"
              placeholder="Search sender, subject..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              style={{
                width: '100%',
                padding: '7px 12px 7px 32px',
                background: 'rgba(15, 23, 42, 0.7)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                color: '#fff',
                fontSize: 12,
                outline: 'none'
              }}
            />
          </div>
        </div>

        {loading ? (
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>Loading security records...</div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
            {investigations.length === 0
              ? "No emails analyzed yet. Click 'Analyze New Message' to evaluate a sample!"
              : "No records match your search query."}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Subject</th>
                  <th>Sender</th>
                  <th>Verdict</th>
                  <th>Score</th>
                  <th>Timestamp</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(inv => {
                  const cls = (inv.classification || '').toLowerCase();
                  const score = Math.round(inv.threat_score || 0);
                  const isHigh = score >= 50;
                  const isSusp = score >= 25 && score < 50;
                  return (
                    <tr key={inv.id}>
                      <td><code>#INV-{inv.id}</code></td>
                      <td style={{ fontWeight: 600, color: '#f8fafc', maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {inv.subject || '(No Subject)'}
                      </td>
                      <td style={{ maxWidth: 200, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--text-secondary)' }}>
                        {inv.sender}
                      </td>
                      <td>
                        <span className={`badge badge-${cls}`}>{inv.classification}</span>
                      </td>
                      <td>
                        <span style={{
                          fontWeight: 800,
                          fontSize: 15,
                          color: isHigh ? 'var(--risk-critical)' : (isSusp ? 'var(--risk-suspicious)' : 'var(--risk-safe)')
                        }}>
                          {score} <span style={{ fontSize: 11, fontWeight: 500, opacity: 0.7 }}>/ 100</span>
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                        {new Date(inv.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '5px 12px', fontSize: 12 }}
                          onClick={() => onSelectInvestigation(inv.id)}
                        >
                          Inspect <ArrowRight size={13} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
