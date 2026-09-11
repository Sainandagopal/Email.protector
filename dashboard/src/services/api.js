const API_BASE = 'http://localhost:8000/api/v1';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function analyzeEmail(payload) {
  const res = await fetch(`${API_BASE}/analyze/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Analysis failed with status ${res.status}`);
  return res.json();
}

export async function getInvestigations() {
  const res = await fetch(`${API_BASE}/investigations`);
  if (!res.ok) throw new Error('Failed to load investigations');
  return res.json();
}

export async function getInvestigationDetail(id) {
  const res = await fetch(`${API_BASE}/investigations/${id}`);
  if (!res.ok) throw new Error('Failed to load investigation detail');
  return res.json();
}

export async function getInvestigationGraph(id) {
  const res = await fetch(`${API_BASE}/investigations/${id}/graph`);
  if (!res.ok) throw new Error('Failed to load attack graph');
  return res.json();
}

export async function generateReport(id) {
  const res = await fetch(`${API_BASE}/reports/${id}`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to generate report');
  return res.json();
}
