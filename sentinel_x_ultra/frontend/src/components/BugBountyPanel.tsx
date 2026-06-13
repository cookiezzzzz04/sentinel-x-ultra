import { useState, useEffect } from 'react';

export function BugBountyPanel({
  projectId,
  addNotification,
  onNavigate,
}: {
  projectId?: string;
  addNotification: (type: string, message: string) => void;
  onNavigate?: (tab: string) => void;
}) {
  const [agents, setAgents] = useState<any[]>([]);
  const [systemPrompt, setSystemPrompt] = useState<string>('');
  const [ethicalRules, setEthicalRules] = useState<any>(null);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineResult, setPipelineResult] = useState<any>(null);
  const [targetDomain, setTargetDomain] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState<any>(null);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookEnabled, setWebhookEnabled] = useState(true);
  const [webhookTestResult, setWebhookTestResult] = useState<any>(null);
  const [webhookLog, setWebhookLog] = useState<any[]>([]);
  const [showWebhookPanel, setShowWebhookPanel] = useState(false);

  useEffect(() => {
    fetch('/api/bug-bounty/agents')
      .then((r) => r.json())
      .then((d) => setAgents(d.agents || []))
      .catch(() => {});
    fetch('/api/bug-bounty/ethical-rules')
      .then((r) => r.json())
      .then(setEthicalRules)
      .catch(() => {});
    fetch('/api/bug-bounty/system-prompt')
      .then((r) => r.json())
      .then((d) => setSystemPrompt(d.principles || ''))
      .catch(() => {});
  }, []);

  const runPipeline = async () => {
    setPipelineRunning(true);
    setPipelineResult(null);
    try {
      const res = await fetch('/api/bug-bounty/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_domain: targetDomain || 'example.com',
          in_scope: ['example.com'],
          project_id: projectId,
        }),
      });
      const data = await res.json();
      setPipelineResult(data);
      setTargetDomain('');
      addNotification(
        data.status === 'completed' ? 'success' : 'error',
        data.status === 'completed'
          ? 'Bug Bounty pipeline completed: ' + (data.findings_count || 0) + ' findings saved'
          : 'Pipeline failed: ' + (data.error || 'unknown error'),
      );
    } catch (e: any) {
      addNotification('error', 'Pipeline error: ' + String(e));
    } finally {
      setPipelineRunning(false);
    }
  };

  const runUrlParse = async () => {
    if (!urlInput.trim()) {
      return;
    }
    try {
      const res = await fetch('/api/bug-bounty/url-parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput }),
      });
      setUrlResult(await res.json());
    } catch (e: any) {
      addNotification('error', 'URL parse failed: ' + String(e));
    }
  };

  const saveWebhookConfig = async () => {
    try {
      const res = await fetch('/api/bug-bounty/webhook/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl, enabled: webhookEnabled }),
      });
      const data = await res.json();
      addNotification(
        data.status === 'ok' ? 'success' : 'error',
        data.message || 'Webhook config saved',
      );
    } catch (e: any) {
      addNotification('error', 'Webhook config error: ' + String(e));
    }
  };

  const testWebhook = async () => {
    setWebhookTestResult(null);
    try {
      const res = await fetch('/api/bug-bounty/webhook/test', { method: 'POST' });
      const data = await res.json();
      setWebhookTestResult(data);
      addNotification(
        data.status === 'ok' ? 'success' : 'error',
        data.success
          ? 'Webhook test sent successfully'
          : 'Webhook test failed: ' + (data.error || 'unknown'),
      );
    } catch (e: any) {
      addNotification('error', 'Webhook test error: ' + String(e));
    }
  };

  const fetchWebhookLog = async () => {
    try {
      const res = await fetch('/api/bug-bounty/webhook/log?limit=10');
      const data = await res.json();
      setWebhookLog(data.deliveries || []);
    } catch (e: any) {
      addNotification('error', 'Failed to fetch webhook log: ' + String(e));
    }
  };

  const agentIcons: Record<number, string> = {
    1: '🌐',
    2: '🛡️',
    3: '🚮',
    4: '🔍',
    5: '🧰',
    6: '🔌',
    7: '✅',
    8: '💥',
    9: '📊',
    10: '📝',
  };

  return (
    <div>
      {/* Header */}
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(170,136,255,0.15), rgba(0,212,255,0.1))',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(170,136,255,0.3)',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>
          <span style={{ fontSize: '40px' }}>🏴</span>
          <div>
            <h2
              style={{
                fontSize: '24px',
                fontWeight: 'bold',
                background: 'linear-gradient(90deg, #aa88ff, #00d4ff)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              Bug Bounty System
            </h2>
            <p style={{ fontSize: '13px', color: '#888' }}>
              Enterprise Multi-Agent Bug Bounty & Security Research System - 10 specialized agents
              with Foundational Principles
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <span
            style={{
              background: 'rgba(170,136,255,0.2)',
              color: '#aa88ff',
              padding: '4px 12px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: '600',
            }}
          >
            10 Agents
          </span>
          <span
            style={{
              background: 'rgba(0,212,255,0.2)',
              color: '#00d4ff',
              padding: '4px 12px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: '600',
            }}
          >
            Ethical Rules
          </span>
          <span
            style={{
              background: 'rgba(0,255,136,0.2)',
              color: '#00ff88',
              padding: '4px 12px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: '600',
            }}
          >
            Decision Hierarchy
          </span>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '24px',
          marginBottom: '24px',
        }}
      >
        {/* 10 Agents Grid */}
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
            10 Specialized Agents
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
            {agents.map((agent: any) => (
              <div
                key={agent.id}
                style={{
                  background: '#1a1a2e',
                  borderRadius: '8px',
                  padding: '12px',
                  border: '1px solid rgba(255,255,255,0.05)',
                }}
              >
                <div style={{ fontSize: '20px', marginBottom: '4px' }}>
                  {agentIcons[agent.id] || '🤖'}
                </div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#00d4ff' }}>
                  {agent.name}
                </div>
                <div style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>
                  {agent.description}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Ethical Rules */}
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
            🛡️ Ethical Rules
          </h3>
          {ethicalRules ? (
            ethicalRules.rules?.map((level: any, i: number) => (
              <div key={i} style={{ marginBottom: '12px' }}>
                <div
                  style={{
                    fontSize: '11px',
                    fontWeight: '600',
                    color: '#ff8844',
                    marginBottom: '4px',
                  }}
                >
                  Level {level.level}: {level.category}
                </div>
                {level.rules?.map((rule: string, j: number) => (
                  <div
                    key={j}
                    style={{
                      fontSize: '11px',
                      color: '#888',
                      paddingLeft: '12px',
                      marginBottom: '2px',
                    }}
                  >
                    {'•'} {rule}
                  </div>
                ))}
              </div>
            ))
          ) : (
            <div style={{ fontSize: '12px', color: '#666' }}>Loading ethical rules...</div>
          )}
          {ethicalRules?.principle && (
            <div
              style={{
                marginTop: '12px',
                padding: '8px',
                background: 'rgba(255,68,68,0.1)',
                borderRadius: '6px',
                fontSize: '11px',
                color: '#ff4444',
                fontWeight: '600',
              }}
            >
              {ethicalRules.principle}
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Pipeline Runner */}
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
            🚀 Run Full Pipeline
          </h3>
          <p style={{ fontSize: '12px', color: '#888', marginBottom: '16px' }}>
            Run all 10 agents in sequence: URL Parser → Policy Enforcer → Scope Guardian → Passive
            Intel → Active Enum → Vuln Scanner → Validation Engine → Exploitation → Analysis →
            Report Generation
          </p>
          <div style={{ marginBottom: '12px' }}>
            <input
              type="text"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="Target domain (e.g. example.com)"
              style={{
                width: '100%',
                padding: '10px',
                borderRadius: '6px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                fontSize: '13px',
              }}
            />
          </div>
          <button
            onClick={runPipeline}
            disabled={pipelineRunning}
            style={{
              width: '100%',
              padding: '14px',
              borderRadius: '10px',
              border: 'none',
              background: pipelineRunning
                ? 'rgba(255,255,255,0.1)'
                : 'linear-gradient(135deg, #aa88ff, #00d4ff)',
              color: pipelineRunning ? '#666' : '#fff',
              fontWeight: '700',
              fontSize: '14px',
              cursor: pipelineRunning ? 'not-allowed' : 'pointer',
            }}
          >
            {pipelineRunning ? '⏳ Scanning...' : '🚀 Scan'}
          </button>
          {pipelineResult && (
            <div style={{ marginTop: '16px' }}>
              {pipelineResult.status === 'completed' ? (
                <>
                  {/* Compact Success Banner */}
                  <div
                    style={{
                      background:
                        'linear-gradient(135deg, rgba(0,255,136,0.1), rgba(0,212,255,0.05))',
                      borderRadius: '12px',
                      padding: '20px',
                      border: '1px solid rgba(0,255,136,0.2)',
                      marginBottom: '12px',
                      textAlign: 'center',
                    }}
                  >
                    <div style={{ fontSize: '36px', marginBottom: '8px' }}>✅</div>
                    <div
                      style={{
                        fontSize: '16px',
                        fontWeight: '700',
                        color: '#00ff88',
                        marginBottom: '4px',
                      }}
                    >
                      Pipeline Complete
                    </div>
                    <div style={{ fontSize: '12px', color: '#888' }}>
                      {pipelineResult.findings_count || 0} findings generated
                      {pipelineResult.message ? ` — ${pipelineResult.message}` : ''}
                    </div>
                  </div>

                  {/* Navigation Buttons */}
                  <div style={{ display: 'flex', gap: '12px' }}>
                    <button
                      onClick={() => onNavigate?.('findings')}
                      style={{
                        flex: 1,
                        padding: '12px',
                        borderRadius: '10px',
                        border: '1px solid rgba(0,212,255,0.3)',
                        background: 'rgba(0,212,255,0.1)',
                        color: '#00d4ff',
                        cursor: 'pointer',
                        fontWeight: '600',
                        fontSize: '13px',
                        transition: 'all 0.2s',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'rgba(0,212,255,0.2)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'rgba(0,212,255,0.1)';
                      }}
                    >
                      🎯 View Findings
                    </button>
                    <button
                      onClick={() => onNavigate?.('ai-report')}
                      style={{
                        flex: 1,
                        padding: '12px',
                        borderRadius: '10px',
                        border: '1px solid rgba(170,136,255,0.3)',
                        background: 'rgba(170,136,255,0.1)',
                        color: '#aa88ff',
                        cursor: 'pointer',
                        fontWeight: '600',
                        fontSize: '13px',
                        transition: 'all 0.2s',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'rgba(170,136,255,0.2)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'rgba(170,136,255,0.1)';
                      }}
                    >
                      📝 View AI Report
                    </button>
                  </div>
                </>
              ) : (
                <div
                  style={{
                    padding: '12px',
                    background: 'rgba(255,68,68,0.1)',
                    borderRadius: '8px',
                    color: '#ff4444',
                    fontSize: '12px',
                  }}
                >
                  ⚠️ {pipelineResult.error || 'Pipeline encountered an error'}
                </div>
              )}
            </div>
          )}
        </div>

        {/* URL Parser Tool */}
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
            🌐 Agent 1: URL Parser
          </h3>
          <p style={{ fontSize: '12px', color: '#888', marginBottom: '12px' }}>
            Parse a HackerOne or BugCrowd program URL to extract program intelligence, scope, and
            policy.
          </p>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://hackerone.com/example"
              style={{
                flex: 1,
                padding: '10px',
                borderRadius: '6px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                fontSize: '12px',
              }}
            />
            <button
              onClick={runUrlParse}
              disabled={!urlInput.trim()}
              style={{
                padding: '10px 16px',
                borderRadius: '6px',
                border: 'none',
                background: urlInput.trim() ? '#aa88ff' : '#333',
                color: '#000',
                cursor: urlInput.trim() ? 'pointer' : 'not-allowed',
                fontWeight: '600',
                fontSize: '12px',
              }}
            >
              Parse
            </button>
          </div>
          {urlResult && (
            <div
              style={{
                maxHeight: '200px',
                overflow: 'auto',
                padding: '12px',
                background: '#1a1a2e',
                borderRadius: '8px',
                fontSize: '11px',
                color: '#00ff88',
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
              }}
            >
              {JSON.stringify(urlResult, null, 2)}
            </div>
          )}
        </div>
      </div>

      {/* Webhook Configuration */}
      <div
        style={{
          marginTop: '24px',
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '16px',
            cursor: 'pointer',
          }}
          onClick={() => setShowWebhookPanel(!showWebhookPanel)}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600' }}>🔔 Webhook Notifications</h3>
          <span style={{ fontSize: '12px', color: webhookUrl ? '#00ff88' : '#888' }}>
            {webhookUrl ? 'Connected' : 'Not configured'} {showWebhookPanel ? '▲' : '▼'}
          </span>
        </div>

        {showWebhookPanel && (
          <div>
            <p style={{ fontSize: '12px', color: '#888', marginBottom: '16px' }}>
              Configure a webhook URL to receive real-time notifications when policy decisions are
              made or when the pipeline completes. Fires for every ALLOW/REVIEW/REJECT decision.
            </p>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input
                type="text"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.example.com/policy-decisions"
                style={{
                  flex: 1,
                  padding: '10px',
                  borderRadius: '6px',
                  border: '1px solid #333',
                  background: '#1a1a2e',
                  color: '#fff',
                  fontSize: '12px',
                }}
              />
              <button
                onClick={saveWebhookConfig}
                disabled={!webhookUrl.trim()}
                style={{
                  padding: '10px 16px',
                  borderRadius: '6px',
                  border: 'none',
                  background: webhookUrl.trim() ? '#aa88ff' : '#333',
                  color: webhookUrl.trim() ? '#000' : '#666',
                  cursor: webhookUrl.trim() ? 'pointer' : 'not-allowed',
                  fontWeight: '600',
                  fontSize: '12px',
                }}
              >
                Save
              </button>
            </div>

            <div
              style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '12px' }}
            >
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '12px',
                  color: '#ccc',
                  cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={webhookEnabled}
                  onChange={(e) => setWebhookEnabled(e.target.checked)}
                  style={{ accentColor: '#aa88ff' }}
                />
                Webhook enabled
              </label>
              <button
                onClick={testWebhook}
                disabled={!webhookUrl.trim() || !webhookEnabled}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  border: '1px solid #00d4ff',
                  background: 'transparent',
                  color: '#00d4ff',
                  cursor: 'pointer',
                  fontSize: '11px',
                  fontWeight: '600',
                }}
              >
                Send Test
              </button>
              <button
                onClick={fetchWebhookLog}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  border: '1px solid #888',
                  background: 'transparent',
                  color: '#888',
                  cursor: 'pointer',
                  fontSize: '11px',
                  fontWeight: '600',
                }}
              >
                View Log
              </button>
            </div>

            {/* Test result */}
            {webhookTestResult && (
              <div
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  marginBottom: '12px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  background: webhookTestResult.success
                    ? 'rgba(0,255,136,0.1)'
                    : 'rgba(255,68,68,0.1)',
                  color: webhookTestResult.success ? '#00ff88' : '#ff4444',
                }}
              >
                {webhookTestResult.success
                  ? `✓ Test delivered: HTTP ${webhookTestResult.status_code}`
                  : `✗ Test failed: ${webhookTestResult.error || 'Unknown error'}`}
              </div>
            )}

            {/* Webhook delivery log */}
            {webhookLog.length > 0 && (
              <div style={{ maxHeight: '150px', overflow: 'auto' }}>
                <div style={{ fontSize: '11px', color: '#666', marginBottom: '6px' }}>
                  Recent deliveries:
                </div>
                {webhookLog.map((entry: any, i: number) => (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '4px 8px',
                      fontSize: '10px',
                      borderBottom: '1px solid rgba(255,255,255,0.03)',
                      color: entry.success ? '#00ff88' : '#ff4444',
                    }}
                  >
                    <span>
                      {entry.event} —{' '}
                      {entry.success ? `HTTP ${entry.status_code}` : entry.error?.slice(0, 40)}
                    </span>
                    <span style={{ color: '#666' }}>{entry.timestamp?.slice(11, 19)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Decision Hierarchy */}
      <div
        style={{
          marginTop: '24px',
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
          🎯 Decision Hierarchy (Priority Order)
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
          {[
            { level: 1, title: 'Legal/Ethical', color: '#ff4444', desc: 'NEVER violated, EVER' },
            { level: 2, title: 'Policy & Scope', color: '#ff8844', desc: 'ALWAYS applied' },
            { level: 3, title: 'Validation', color: '#ffaa00', desc: 'STRICTLY enforced' },
            { level: 4, title: 'Report Quality', color: '#00d4ff', desc: 'MAINTAINED' },
            { level: 5, title: 'Efficiency', color: '#888', desc: 'ADJUSTED' },
          ].map((h) => (
            <div
              key={h.level}
              style={{
                background: '#1a1a2e',
                borderRadius: '8px',
                padding: '12px',
                textAlign: 'center',
                borderLeft: `3px solid ${h.color}`,
              }}
            >
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>
                LEVEL {h.level}
              </div>
              <div
                style={{ fontSize: '13px', fontWeight: '600', color: h.color, marginBottom: '4px' }}
              >
                {h.title}
              </div>
              <div style={{ fontSize: '10px', color: '#888' }}>{h.desc}</div>
            </div>
          ))}
        </div>
        <div
          style={{
            marginTop: '12px',
            padding: '8px 12px',
            background: 'rgba(255,68,68,0.1)',
            borderRadius: '6px',
            fontSize: '11px',
            color: '#ff4444',
            fontWeight: '600',
            textAlign: 'center',
          }}
        >
          CRITICAL RULE: Lower levels NEVER override higher levels
        </div>
      </div>
    </div>
  );
}
