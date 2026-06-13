import { useState } from 'react';

function getPhase5Capabilities(agentId: string): string[] {
  switch (agentId) {
    case 'threat_intelligence':
      return [
        'YARA rule scanning',
        'IOC enrichment',
        'Threat actor tracking',
        'VirusTotal integration',
        'Malware analysis',
      ];
    case 'security_operations':
      return [
        'SIEM log analysis',
        'SOAR playbook execution',
        'Event correlation',
        'Incident management',
        'Alert triage',
      ];
    case 'adaptive_defense':
      return [
        'ML anomaly detection',
        'Behavioral analysis',
        'Self-healing automation',
        'Threat feed integration',
        'Real-time blocking',
      ];
    case 'supply_chain':
      return [
        'SBOM generation',
        'Dependency graph analysis',
        'License compliance',
        'CVE vulnerability scanning',
        'Provenance tracking',
      ];
    case 'api_security':
      return [
        'OpenAPI/GraphQL analysis',
        'Authentication testing',
        'Authorization bypass',
        'Rate limiting validation',
        'Fuzzing automation',
      ];
    default:
      return [];
  }
}

export function Phase5Panel({
  projectId,
  selectedAgent,
  onSelectAgent,
}: {
  projectId: string;
  selectedAgent: string;
  onSelectAgent: (agent: string) => void;
}) {
  const phase5Agents = [
    {
      id: 'threat_intelligence',
      name: '🔍 Threat Intelligence',
      description: 'YARA rules, IOC enrichment, threat tracking',
      color: '#ff8844',
    },
    {
      id: 'security_operations',
      name: '🛡️ Security Operations',
      description: 'SIEM integration, SOAR playbooks',
      color: '#00d4ff',
    },
    {
      id: 'adaptive_defense',
      name: '⚡ Adaptive Defense',
      description: 'ML anomaly detection, self-healing',
      color: '#aa88ff',
    },
    {
      id: 'supply_chain',
      name: '📦 Supply Chain',
      description: 'SBOM generation, license compliance',
      color: '#00ff88',
    },
    {
      id: 'api_security',
      name: '🔗 API Security',
      description: 'OpenAPI analysis, fuzzing, auth testing',
      color: '#ffaa00',
    },
  ];

  const [phase5Output, setPhase5Output] = useState<string>('');
  const [runningPhase5, setRunningPhase5] = useState<string | null>(null);

  const runPhase5Agent = async (agentType: string) => {
    setRunningPhase5(agentType);
    setPhase5Output('Initializing Phase 5 agent...');
    try {
      const res = await fetch(`/api/projects/${projectId}/agents/${agentType.replace(/_/g, '-')}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'analyze', input_data: { scope: 'full' } }),
      });
      const data = await res.json();
      setPhase5Output(JSON.stringify(data, null, 2));
    } catch (e) {
      setPhase5Output(`Error: ${e}`);
    } finally {
      setRunningPhase5(null);
    }
  };

  return (
    <div>
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(255, 136, 68, 0.1), rgba(255, 68, 136, 0.05))',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255, 136, 68, 0.2)',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <span style={{ fontSize: '24px' }}>🚀</span>
          <div>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 'bold',
                background: 'linear-gradient(90deg, #ff8844, #ff4488)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              Phase 5 Security Suite
            </h3>
            <p style={{ fontSize: '12px', color: '#666' }}>
              Advanced threat hunting, operations, and defense automation
            </p>
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
          {phase5Agents.map((agent) => (
            <button
              key={agent.id}
              onClick={() => {
                onSelectAgent(agent.id);
                runPhase5Agent(agent.id);
              }}
              disabled={runningPhase5 !== null}
              style={{
                background: selectedAgent === agent.id ? `${agent.color}20` : 'rgba(0,0,0,0.3)',
                border: `1px solid ${selectedAgent === agent.id ? agent.color : 'rgba(255,255,255,0.1)'}`,
                borderRadius: '12px',
                padding: '16px',
                cursor: runningPhase5 ? 'not-allowed' : 'pointer',
                opacity: runningPhase5 && selectedAgent !== agent.id ? 0.5 : 1,
                transition: 'all 0.2s',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '24px', marginBottom: '8px' }}>
                {agent.name.split(' ')[0]}
              </div>
              <div style={{ fontSize: '12px', fontWeight: '600', color: agent.color }}>
                {agent.name.split(' ').slice(1).join(' ')}
              </div>
              <div style={{ fontSize: '10px', color: '#666', marginTop: '4px' }}>
                {agent.description.split(',')[0]}
              </div>
            </button>
          ))}
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
            {phase5Agents.find((a) => a.id === selectedAgent)?.name || 'Select Agent'}
          </h3>
          <p style={{ fontSize: '13px', color: '#666', marginBottom: '16px' }}>
            {phase5Agents.find((a) => a.id === selectedAgent)?.description}
          </p>
          <div
            style={{
              background: 'rgba(0,0,0,0.3)',
              borderRadius: '8px',
              padding: '16px',
              marginBottom: '16px',
            }}
          >
            <h4
              style={{ fontSize: '13px', fontWeight: '600', marginBottom: '12px', color: '#888' }}
            >
              Capabilities
            </h4>
            {getPhase5Capabilities(selectedAgent).map((cap, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginBottom: '8px',
                  fontSize: '13px',
                  color: '#aaa',
                }}
              >
                <span style={{ color: '#00ff88' }}>✓</span> {cap}
              </div>
            ))}
          </div>
          <button
            onClick={() => runPhase5Agent(selectedAgent)}
            disabled={runningPhase5 !== null}
            style={{
              width: '100%',
              background: runningPhase5
                ? 'rgba(255,255,255,0.1)'
                : 'linear-gradient(135deg, #ff8844, #ff4488)',
              color: runningPhase5 ? '#666' : '#fff',
              border: 'none',
              borderRadius: '10px',
              padding: '14px',
              fontWeight: '700',
              cursor: runningPhase5 ? 'not-allowed' : 'pointer',
              fontSize: '14px',
            }}
          >
            {runningPhase5 ? '⏳ Running...' : '▶ Run Analysis'}
          </button>
        </div>
        <div
          style={{
            background: 'rgba(10, 10, 15, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
            Analysis Output
          </h3>
          <div
            style={{
              minHeight: '300px',
              maxHeight: '400px',
              overflow: 'auto',
              fontFamily: 'monospace',
              fontSize: '12px',
              color: '#00ff88',
              background: 'rgba(0,0,0,0.3)',
              borderRadius: '8px',
              padding: '16px',
              whiteSpace: 'pre-wrap',
            }}
          >
            {phase5Output || 'Run an agent to see output here...'}
          </div>
        </div>
      </div>
    </div>
  );
}
