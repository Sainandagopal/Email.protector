import React, { useState } from 'react';

export default function AttackGraph({ graphData = { nodes: [], edges: [] } }) {
  const [selectedNode, setSelectedNode] = useState(null);

  const { nodes = [], edges = [] } = graphData;

  // Compute hierarchical column layout coordinates
  // Col 1: Sender | Col 2: Mail Relay/IP | Col 3: URLs & Domains | Col 4: Recipient Target
  const typeCounters = { sender: 0, ip: 0, url: 0, recipient: 0, other: 0 };

  const layoutNodes = nodes.map((n) => {
    let col = 1;
    if (n.type === 'sender') col = 1;
    else if (n.type === 'ip') col = 2;
    else if (n.type === 'url') col = 3;
    else if (n.type === 'recipient') col = 4;
    else col = 3;

    const slot = typeCounters[n.type] || 0;
    typeCounters[n.type] = slot + 1;

    const x = 110 + (col - 1) * 210;
    const y = 75 + slot * 95;

    return { ...n, x, y };
  });

  const nodeMap = {};
  layoutNodes.forEach(n => { nodeMap[n.id] = n; });

  const getNodeColor = (type, risk) => {
    if (risk === 'critical' || risk === 'malicious' || risk === 'phishing') return '#ef4444';
    if (risk === 'high' || risk === 'suspicious') return '#f59e0b';
    if (type === 'sender') return '#7c5cff';
    if (type === 'ip') return '#0071e3';
    if (type === 'recipient') return '#10b981';
    return '#10b981';
  };

  const getNodeEmoji = (type) => {
    if (type === 'sender') return '👤';
    if (type === 'ip') return '🌐';
    if (type === 'recipient') return '🎯';
    return '🔗';
  };

  return (
    <div className="attack-graph-container" style={{ position: 'relative', width: '100%', overflowX: 'auto', borderRadius: 16, padding: '20px 16px' }}>
      <svg width="840" height="340" style={{ display: 'block', margin: '0 auto' }}>
        <defs>
          <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#7c5cff" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#0071e3" stopOpacity="0.8" />
          </linearGradient>
          <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#0071e3" />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((e, idx) => {
          const s = nodeMap[e.source];
          const t = nodeMap[e.target];
          if (!s || !t) return null;
          return (
            <g key={idx}>
              <line
                x1={s.x}
                y1={s.y}
                x2={t.x}
                y2={t.y}
                stroke="rgba(0, 113, 227, 0.45)"
                strokeWidth="2"
                strokeDasharray="4, 4"
                markerEnd="url(#arrow)"
              />
              <text
                x={(s.x + t.x) / 2}
                y={(s.y + t.y) / 2 - 8}
                fill="var(--text-secondary)"
                fontSize="10"
                fontWeight="600"
                textAnchor="middle"
                fontFamily="monospace"
              >
                {e.label}
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {layoutNodes.map(n => {
          const color = getNodeColor(n.type, n.risk);
          const isSelected = selectedNode && selectedNode.id === n.id;
          return (
            <g
              key={n.id}
              transform={`translate(${n.x}, ${n.y})`}
              onClick={() => setSelectedNode(n)}
              style={{ cursor: 'pointer' }}
            >
              <circle
                r={isSelected ? 26 : 22}
                stroke={color}
                strokeWidth={isSelected ? 3.5 : 2.5}
                className="graph-circle-node"
              />
              <text
                y="5"
                textAnchor="middle"
                fontSize="14"
              >
                {getNodeEmoji(n.type)}
              </text>
              <text
                y="38"
                textAnchor="middle"
                fontSize="11"
                fontWeight="700"
                className="graph-label-text"
              >
                {n.label}
              </text>
              {n.sub && (
                <text
                  y="52"
                  textAnchor="middle"
                  fontSize="9.5"
                  fontWeight="500"
                  className="graph-sub-text"
                >
                  {n.sub}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Selected Node Details popup */}
      {selectedNode && (
        <div style={{
          marginTop: 14,
          padding: '12px 16px',
          background: 'var(--bg-inner-subtle)',
          borderLeft: `4px solid ${getNodeColor(selectedNode.type, selectedNode.risk)}`,
          borderRadius: '0 12px 12px 0',
          fontSize: 12.5,
          color: 'var(--text-primary)'
        }}>
          <strong>Selected Entity:</strong> {selectedNode.label} &bull; <span style={{ textTransform: 'uppercase', fontWeight: 600 }}>Type: {selectedNode.type}</span> &bull; <span>Threat Severity: <strong style={{ color: getNodeColor(selectedNode.type, selectedNode.risk) }}>{selectedNode.risk.toUpperCase()}</strong></span>
          {selectedNode.sub && <div style={{ color: 'var(--text-secondary)', marginTop: 4 }}>Details: {selectedNode.sub}</div>}
        </div>
      )}
    </div>
  );
}
