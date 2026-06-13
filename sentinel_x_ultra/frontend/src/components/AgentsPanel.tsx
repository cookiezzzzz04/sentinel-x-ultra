export function AgentsPanel({
  runningAgent,
  onRunAgent,
  output,
}: {
  runningAgent: string | null;
  onRunAgent: (agent: string, action: string, data: any) => void;
  output: string;
}) {
  const agents = [
    {
      id: 'recon',
      name: '🎯 Recon Agent',
      description: 'Target discovery, port scanning, OSINT',
      color: '#00d4ff',
    },
    {
      id: 'code-review',
      name: '🔍 Code Review Agent',
      description: 'SAST with security pattern detection',
      color: '#00ff88',
    },
    {
      id: 'threat-modeling',
      name: '🛡️ Threat Modeling Agent',
      description: 'Attack path analysis using knowledge graph',
      color: '#ff8844',
    },
    {
      id: 'dependency',
      name: '📦 Dependency Agent',
      description: 'Vulnerability scanning for dependencies',
      color: '#aa88ff',
    },
    {
      id: 'debate',
      name: '⚖️ Debate Engine',
      description: '5-role adversarial finding validation',
      color: '#ffaa00',
    },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      <div>
        <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>Phase 3 Agents</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {agents.map((agent) => (
            <div
              key={agent.id}
              style={{
                background: 'rgba(15, 15, 26, 0.95)',
                border: `1px solid ${agent.color}40`,
                borderRadius: '12px',
                padding: '16px',
                cursor: runningAgent ? 'not-allowed' : 'pointer',
                opacity: runningAgent ? 0.6 : 1,
                transition: 'all 0.2s',
              }}
              onClick={() =>
                !runningAgent &&
                onRunAgent(agent.id, 'discover', { scope: { domains: ['example.com'] } })
              }
              onMouseEnter={(e) => {
                if (!runningAgent) {
                  e.currentTarget.style.borderColor = agent.color;
                  e.currentTarget.style.transform = 'translateX(4px)';
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = `${agent.color}40`;
                e.currentTarget.style.transform = 'translateX(0)';
              }}
            >
              <div
                style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
              >
                <div style={{ fontSize: '16px', fontWeight: '600', color: agent.color }}>
                  {agent.name}
                </div>
                {runningAgent === agent.id && (
                  <span style={{ fontSize: '12px', color: '#888', animation: 'pulse 1s infinite' }}>
                    Running...
                  </span>
                )}
              </div>
              <p style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                {agent.description}
              </p>
            </div>
          ))}
        </div>
        <div
          style={{
            marginTop: '16px',
            padding: '12px',
            background: 'rgba(0, 212, 255, 0.1)',
            borderRadius: '8px',
            fontSize: '12px',
            color: '#00d4ff',
          }}
        >
          💡 Click an agent to run it with default parameters.
        </div>
      </div>
      <div>
        <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>Agent Output</h3>
        <div
          style={{
            background: 'rgba(10, 10, 15, 0.95)',
            border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: '12px',
            padding: '16px',
            minHeight: '400px',
            maxHeight: '500px',
            overflow: 'auto',
            fontFamily: 'monospace',
            fontSize: '12px',
            whiteSpace: 'pre-wrap',
            color: output.includes('error') || output.includes('Error') ? '#ff4444' : '#00ff88',
          }}
        >
          {output || 'Run an agent to see output here...'}
        </div>
      </div>
    </div>
  );
}
