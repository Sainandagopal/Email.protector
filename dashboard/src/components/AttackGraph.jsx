import React, { useState } from 'react';

export default function AttackGraph({ graphData = { nodes: [], edges: [] } }) {
  const [selectedNode, setSelectedNode] = useState(null);

  const { nodes = [], edges = [] } = graphData;

  // Group and count nodes per column to compute dynamic height & positions
  const colGroups = { sender: [], ip: [], url: [], recipient: [] };
  nodes.forEach(n => {
    const t = n.type === 'sender' || n.type === 'ip' || n.type === 'url' || n.type === 'recipient' ? n.type : 'url';
    colGroups[t].push(n);
  });

  const maxInCol = Math.max(
    colGroups.sender.length,
    colGroups.ip.length,
    colGroups.url.length,
    colGroups.recipient.length,
    1
  );

  const rowHeight = 115;
  const topOffset = 85;
  const svgHeight = Math.max(380, topOffset + maxInCol * rowHeight + 35);
  const svgWidth = 940;

  const colX = {
    sender: 125,
    ip: 375,
    url: 625,
    recipient: 840
  };

  const layoutNodes = nodes.map(n => {
    const t = n.type in colX ? n.type : 'url';
    const group = colGroups[t];
    const idx = group.findIndex(item => item.id === n.id);
    const count = group.length;

    // Center nodes vertically within column
    const colTotalHeight = count * rowHeight;
    const startY = topOffset + (maxInCol * rowHeight - colTotalHeight) / 2 + 40;
    const y = startY + idx * rowHeight;
    const x = colX[t];

    return { ...n, x, y };
  });

  const nodeMap = {};
  layoutNodes.forEach(n => { nodeMap[n.id] = n; });

  const getNodeColor = (type, risk) => {
    if (risk === 'critical' || risk === 'malicious' || risk === 'phishing') return '#ef4444';
    if (risk === 'high' || risk === 'suspicious') return '#f59e0b';
    if (type === 'sender') return '#a855f7';
    if (type === 'ip') return '#0284c7';
    if (type === 'recipient') return '#10b981';
    return '#38bdf8';
  };

  const getHumanFriendlyLabel = (label) => {
    if (!label) return 'Connected To';
    const clean = label.toLowerCase().replace(/_/g, ' ').trim();
    if (clean.includes('originated') || clean.includes('sent via')) return 'Sent Via';
    if (clean.includes('relay')) return 'Relayed To';
    if (clean.includes('link') || clean.includes('embed') || clean.includes('carries')) return 'Carries Link';
    if (clean.includes('domain') || clean.includes('hosted')) return 'Hosted On';
    if (clean.includes('deliver') || clean.includes('inbox')) return 'Delivered To';
    return label;
  };

  // Plain-English Story Generation
  const senderNode = layoutNodes.find(n => n.type === 'sender') || { label: 'Unknown Sender' };
  const relayNodes = layoutNodes.filter(n => n.type === 'ip');
  const threatNodes = layoutNodes.filter(n => n.type === 'url');
  const recipientNode = layoutNodes.find(n => n.type === 'recipient') || { label: 'Recipient Inbox' };

  return (
    <div className="attack-graph-container" style={{ width: '100%', overflowX: 'auto', borderRadius: 16 }}>
      {/* Visual Stepper Banner */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 12,
        marginBottom: 16,
        padding: '12px 14px',
        background: 'rgba(15, 23, 42, 0.7)',
        borderRadius: 12,
        border: '1px solid var(--border-subtle)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ background: 'rgba(168, 85, 247, 0.2)', color: '#c084fc', padding: '4px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>STEP 1</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#fff' }}>Who Sent It?</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>Origin identity / sender</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ background: 'rgba(2, 132, 199, 0.2)', color: '#38bdf8', padding: '4px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>STEP 2</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#fff' }}>How It Traveled</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>Mail servers & routing</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', padding: '4px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>STEP 3</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#fff' }}>What It Carries</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>Suspicious links & threats</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '4px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>STEP 4</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#fff' }}>Target Victim</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>Your destination inbox</div>
          </div>
        </div>
      </div>

      {/* Main Graph SVG Canvas */}
      <svg width={svgWidth} height={svgHeight} style={{ display: 'block', margin: '0 auto', background: 'rgba(10, 14, 26, 0.85)', borderRadius: 14, border: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <defs>
          <linearGradient id="curveGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#818cf8" stopOpacity="0.8" />
          </linearGradient>

          <marker id="arrowHead" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" />
          </marker>

          <filter id="nodeGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="0" stdDeviation="4" floodOpacity="0.5" />
          </filter>
        </defs>

        {/* Column Swimlane Tracks */}
        {[
          { name: '1. SENDER', x: 25, w: 200, color: 'rgba(168, 85, 247, 0.06)', border: 'rgba(168, 85, 247, 0.2)' },
          { name: '2. MAIL ROUTING', x: 275, w: 200, color: 'rgba(2, 132, 199, 0.06)', border: 'rgba(2, 132, 199, 0.2)' },
          { name: '3. DETECTED THREATS', x: 525, w: 200, color: 'rgba(239, 68, 68, 0.06)', border: 'rgba(239, 68, 68, 0.2)' },
          { name: '4. DESTINATION', x: 750, w: 175, color: 'rgba(16, 185, 129, 0.06)', border: 'rgba(16, 185, 129, 0.2)' },
        ].map((lane, idx) => (
          <g key={idx}>
            <rect
              x={lane.x}
              y={14}
              width={lane.w}
              height={svgHeight - 28}
              rx={12}
              fill={lane.color}
              stroke={lane.border}
              strokeWidth="1"
              strokeDasharray="4, 4"
            />
            <rect
              x={lane.x + (lane.w - 120) / 2}
              y={24}
              width={120}
              height={22}
              rx={11}
              fill="rgba(15, 23, 42, 0.9)"
              stroke={lane.border}
              strokeWidth="1"
            />
            <text
              x={lane.x + lane.w / 2}
              y={39}
              textAnchor="middle"
              fill="#cbd5e1"
              fontSize="10"
              fontWeight="800"
              letterSpacing="0.05em"
            >
              {lane.name}
            </text>
          </g>
        ))}

        {/* Curved Connections (Edges) */}
        {edges.map((e, idx) => {
          const s = nodeMap[e.source];
          const t = nodeMap[e.target];
          if (!s || !t) return null;

          const dx = Math.max(50, Math.abs(t.x - s.x) * 0.45);
          const pathData = `M ${s.x} ${s.y} C ${s.x + dx} ${s.y}, ${t.x - dx} ${t.y}, ${t.x} ${t.y}`;
          const midX = (s.x + t.x) / 2;
          const midY = (s.y + t.y) / 2;

          const friendlyLabel = getHumanFriendlyLabel(e.label);
          const pillWidth = friendlyLabel.length * 6.5 + 18;

          return (
            <g key={idx}>
              <path
                d={pathData}
                fill="none"
                stroke="url(#curveGrad)"
                strokeWidth="2.5"
                strokeDasharray="6, 4"
                markerEnd="url(#arrowHead)"
              />
              {/* Friendly connection badge pill */}
              <rect
                x={midX - pillWidth / 2}
                y={midY - 10}
                width={pillWidth}
                height={20}
                rx={10}
                fill="#0f172a"
                stroke="rgba(56, 189, 248, 0.4)"
                strokeWidth="1.5"
              />
              <text
                x={midX}
                y={midY + 3.5}
                fill="#38bdf8"
                fontSize="9.5"
                fontWeight="700"
                textAnchor="middle"
              >
                {friendlyLabel}
              </text>
            </g>
          );
        })}

        {/* Graph Nodes */}
        {layoutNodes.map(n => {
          const color = getNodeColor(n.type, n.risk);
          const isSelected = selectedNode && selectedNode.id === n.id;
          const radius = isSelected ? 26 : 22;

          return (
            <g
              key={n.id}
              transform={`translate(${n.x}, ${n.y})`}
              onClick={() => setSelectedNode(n)}
              style={{ cursor: 'pointer' }}
            >
              {/* Outer pulsing ring for selected */}
              {isSelected && (
                <circle
                  r={32}
                  fill="none"
                  stroke={color}
                  strokeWidth="2"
                  strokeDasharray="3, 3"
                  opacity="0.8"
                />
              )}

              {/* Main Node Circle */}
              <circle
                r={radius}
                fill="#0f172a"
                stroke={color}
                strokeWidth={isSelected ? 3.5 : 2.5}
                filter="url(#nodeGlow)"
              />

              {/* Crisp SVG Icons */}
              {n.type === 'sender' && (
                <path
                  d="M -7 7 A 7 7 0 0 1 7 7 M 0 -1 A 4.5 4.5 0 1 1 0 -9 A 4.5 4.5 0 0 1 0 -1"
                  fill="none"
                  stroke="#c084fc"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              )}
              {n.type === 'ip' && (
                <g stroke="#38bdf8" strokeWidth="1.5" fill="none">
                  <circle cx="0" cy="0" r="7.5" />
                  <ellipse cx="0" cy="0" rx="3.5" ry="7.5" />
                  <line x1="-7.5" y1="0" x2="7.5" y2="0" />
                </g>
              )}
              {n.type === 'url' && (
                <path
                  d="M -5 3 L 5 -5 M 0 -7 L 6 -7 L 6 -1 M -6 0 L -6 6 L 0 6"
                  fill="none"
                  stroke="#f87171"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
              {n.type === 'recipient' && (
                <path
                  d="M -7 -4 L 7 -4 L 7 5 L -7 5 Z M -7 -4 L 0 1.5 L 7 -4"
                  fill="none"
                  stroke="#34d399"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}

              {/* Node Title */}
              <text
                y={radius + 15}
                textAnchor="middle"
                fill="#ffffff"
                fontSize="11.5"
                fontWeight="700"
              >
                {n.label.length > 20 ? `${n.label.slice(0, 19)}…` : n.label}
              </text>

              {/* Node Subtitle */}
              {n.sub && (
                <text
                  y={radius + 28}
                  textAnchor="middle"
                  fill="#94a3b8"
                  fontSize="9.5"
                  fontWeight="500"
                >
                  {n.sub.length > 24 ? `${n.sub.slice(0, 23)}…` : n.sub}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Bottom: Plain English Story of the Email */}
      <div style={{
        marginTop: 14,
        padding: '16px 20px',
        background: 'rgba(15, 23, 42, 0.75)',
        borderRadius: 12,
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        gap: 8
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 700, color: '#38bdf8' }}>
          <span>📖</span>
          <span>How this email traveled (Plain English Breakdown):</span>
        </div>

        <div style={{ fontSize: 13, color: '#e2e8f0', lineHeight: 1.6 }}>
          1. <strong>Sender:</strong> The message arrived purporting to be from <strong>{senderNode.label}</strong> {senderNode.sub ? `(${senderNode.sub})` : ''}.<br />
          2. <strong>Transmission:</strong> It routed through mail server relay <strong>{relayNodes.map(r => r.label).join(', ') || 'verified gateway'}</strong>.<br />
          3. <strong>Embedded Payload:</strong> {threatNodes.length > 0
            ? <>It contained <strong>{threatNodes.length} suspicious link(s)</strong> (such as <code>{threatNodes[0].label}</code>) designed to redirect the victim.</>
            : <>No suspicious hyperlinks or redirects were found inside the message content.</>
          }<br />
          4. <strong>Delivery:</strong> The email was delivered directly to target mailbox <strong>{recipientNode.label}</strong>.
        </div>

        {selectedNode && (
          <div style={{
            marginTop: 8,
            padding: '10px 14px',
            background: 'rgba(30, 41, 59, 0.8)',
            borderLeft: `4px solid ${getNodeColor(selectedNode.type, selectedNode.risk)}`,
            borderRadius: '0 8px 8px 0',
            fontSize: 12,
            color: '#cbd5e1'
          }}>
            <strong style={{ color: '#fff' }}>Selected Item:</strong> {selectedNode.label} &bull; <span style={{ textTransform: 'uppercase' }}>Type: {selectedNode.type}</span> &bull; Threat Level: <strong style={{ color: getNodeColor(selectedNode.type, selectedNode.risk) }}>{selectedNode.risk?.toUpperCase() || 'SAFE'}</strong>
            {selectedNode.sub && <div style={{ color: '#94a3b8', marginTop: 2 }}>Details: {selectedNode.sub}</div>}
          </div>
        )}
      </div>
    </div>
  );
}
