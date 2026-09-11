import React, { useState, useEffect } from 'react';
import { 
  Shield, Activity, PlusCircle, FileText, Globe, 
  ExternalLink, Cpu, Info 
} from 'lucide-react';
import { fetchHealth } from './services/api';
import Overview from './pages/Overview';
import AnalyzeEmail from './pages/AnalyzeEmail';
import InvestigationDetail from './pages/InvestigationDetail';

export default function App() {
  const [currentView, setCurrentView] = useState('overview'); // overview, analyze, detail, help
  const [selectedInvestigationId, setSelectedInvestigationId] = useState(null);
  const [backendOnline, setBackendOnline] = useState(false);

  // Check URL path or query parameter for direct case loading
  useEffect(() => {
    const path = window.location.pathname;
    const searchParams = new URLSearchParams(window.location.search);
    
    if (path.startsWith('/investigations/')) {
      const id = parseInt(path.split('/investigations/')[1], 10);
      if (id) {
        setSelectedInvestigationId(id);
        setCurrentView('detail');
      }
    } else if (searchParams.get('case_id')) {
      const id = parseInt(searchParams.get('case_id'), 10);
      if (id) {
        setSelectedInvestigationId(id);
        setCurrentView('detail');
      }
    }

    // Health ping
    async function checkStatus() {
      try {
        const h = await fetchHealth();
        if (h.status === 'online') setBackendOnline(true);
      } catch {
        setBackendOnline(false);
      }
    }
    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectInvestigation = (id) => {
    setSelectedInvestigationId(id);
    setCurrentView('detail');
    window.history.pushState({}, '', `/investigations/${id}`);
  };

  const handleAnalysisComplete = (id) => {
    handleSelectInvestigation(id);
  };

  const handleNavigate = (view) => {
    setCurrentView(view);
    if (view === 'overview') {
      window.history.pushState({}, '', '/');
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand-header">
          <div className="brand-logo-icon">
            <Shield size={20} />
          </div>
          <div>
            <div className="brand-title">SIH-Guard</div>
            <div className="brand-sub">Security Platform</div>
          </div>
        </div>

        <ul className="nav-links">
          <li>
            <button
              className={`nav-item-btn ${currentView === 'overview' ? 'active' : ''}`}
              onClick={() => handleNavigate('overview')}
            >
              <Activity size={16} /> Security Hub
            </button>
          </li>
          <li>
            <button
              className={`nav-item-btn ${currentView === 'analyze' ? 'active' : ''}`}
              onClick={() => handleNavigate('analyze')}
            >
              <PlusCircle size={16} /> Analyze Message
            </button>
          </li>
          {selectedInvestigationId && (
            <li>
              <button
                className={`nav-item-btn ${currentView === 'detail' ? 'active' : ''}`}
                onClick={() => handleNavigate('detail')}
              >
                <FileText size={16} /> Active Dossier
              </button>
            </li>
          )}
        </ul>

        {/* Status Indicator in Sidebar */}
        <div className="sidebar-status">
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 4 }}>
            <span
              className="pulse-dot"
              style={{
                background: backendOnline ? 'var(--risk-safe)' : 'var(--risk-critical)',
                boxShadow: `0 0 8px ${backendOnline ? 'var(--risk-safe)' : 'var(--risk-critical)'}`
              }}
            />
            <strong style={{ color: '#fff', fontSize: '12px' }}>{backendOnline ? 'Core API Connected' : 'Core API Offline'}</strong>
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
            Port 8000 &bull; Database Active
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Top bar */}
        <header className="top-bar">
          <div>
            <div className="view-title">
              {currentView === 'overview' && 'Security Analytics & Threat Monitoring'}
              {currentView === 'analyze' && 'Message Ingestion & Threat Analysis'}
              {currentView === 'detail' && 'Forensic Investigation Dossier'}
            </div>
            <div className="view-subtitle">Real-time AI email threat detection and origin intelligence</div>
          </div>
        </header>

        {/* View content */}
        <div className="content-body">
          {currentView === 'overview' && (
            <Overview
              onSelectInvestigation={handleSelectInvestigation}
              onNavigateToAnalyze={() => handleNavigate('analyze')}
            />
          )}

          {currentView === 'analyze' && (
            <AnalyzeEmail onAnalysisComplete={handleAnalysisComplete} />
          )}

          {currentView === 'detail' && selectedInvestigationId && (
            <InvestigationDetail
              investigationId={selectedInvestigationId}
              onBack={() => handleNavigate('overview')}
            />
          )}
        </div>
      </main>
    </div>
  );
}
