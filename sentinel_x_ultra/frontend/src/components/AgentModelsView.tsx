import { useState, useEffect } from 'react';

export function AgentModelsView() {
  const [agentModels, setAgentModels] = useState<Record<string, string>>({});
  const [defaults, setDefaults] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const agentCategories = [
    {
      name: 'Reconnaissance',
      agents: ['recon', 'passive_recon', 'active_recon', 'osint'],
      color: '#00d4ff',
    },
    { name: 'Code Analysis', agents: ['code_review', 'sast', 'dependency'], color: '#00ff88' },
    {
      name: 'Threat Modeling',
      agents: ['threat_modeling', 'attack_path', 'risk_assessment'],
      color: '#ff8844',
    },
    { name: 'Advanced', agents: ['debate', 'remediation', 'exploitation'], color: '#aa88ff' },
    { name: 'Validation', agents: ['validation', 'report_generation'], color: '#ffaa00' },
  ];

  const fetchModels = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/agent-models');
      if (!res.ok) throw new Error('Failed to fetch');
      const data = await res.json();
      setAgentModels(data.models || {});
      setDefaults(data.defaults || {});
    } catch (e) {
      setError('Failed to load agent models');
    } finally {
      setLoading(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await fetch('/api/agent-models', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ models: agentModels }),
      });
      if (!res.ok) throw new Error('Failed to save');
      setSuccess('Models saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (e) {
      setError('Failed to save models');
    } finally {
      setSaving(false);
    }
  };

  const reset = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch('/api/agent-models/reset', { method: 'POST' });
      if (!res.ok) throw new Error('Failed to reset');
      const data = await res.json();
      setAgentModels(data.models || {});
      setSuccess('Models reset to defaults');
      setTimeout(() => setSuccess(null), 3000);
    } catch (e) {
      setError('Failed to reset models');
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    fetchModels();
  }, []);

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '24px',
        }}
      >
        <div>
          <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '4px' }}>
            🤖 Agent Models
          </h2>
          <p style={{ fontSize: '13px', color: '#666' }}>
            Configure which model each agent uses. Defaults from provider settings.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={reset}
            disabled={saving}
            style={{
              padding: '10px 20px',
              borderRadius: '8px',
              border: '1px solid rgba(255,255,255,0.1)',
              background: 'rgba(255,255,255,0.05)',
              color: '#888',
              cursor: saving ? 'not-allowed' : 'pointer',
              fontWeight: '600',
              fontSize: '13px',
            }}
          >
            Reset Defaults
          </button>
          <button
            onClick={save}
            disabled={saving}
            style={{
              padding: '10px 20px',
              borderRadius: '8px',
              border: 'none',
              background: saving
                ? 'rgba(255,255,255,0.1)'
                : 'linear-gradient(135deg, #00d4ff, #00ff88)',
              color: saving ? '#666' : '#000',
              cursor: saving ? 'not-allowed' : 'pointer',
              fontWeight: '700',
              fontSize: '13px',
            }}
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '12px',
            background: 'rgba(255,68,68,0.1)',
            borderRadius: '8px',
            color: '#ff4444',
            marginBottom: '16px',
            fontSize: '13px',
          }}
        >
          {error}
        </div>
      )}
      {success && (
        <div
          style={{
            padding: '12px',
            background: 'rgba(0,255,136,0.1)',
            borderRadius: '8px',
            color: '#00ff88',
            marginBottom: '16px',
            fontSize: '13px',
          }}
        >
          {success}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: '48px', color: '#666' }}>Loading...</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {agentCategories.map((cat) => (
            <div
              key={cat.name}
              style={{
                background: 'rgba(15, 15, 26, 0.95)',
                borderRadius: '16px',
                padding: '24px',
                border: '1px solid rgba(255,255,255,0.05)',
              }}
            >
              <h3
                style={{
                  fontSize: '15px',
                  fontWeight: '600',
                  marginBottom: '16px',
                  color: cat.color,
                }}
              >
                {cat.name}
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {cat.agents.map((agentId) => {
                  const current = agentModels[agentId] || defaults[agentId] || '';
                  const isCustom =
                    agentModels[agentId] && agentModels[agentId] !== defaults[agentId];
                  return (
                    <div
                      key={agentId}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '8px 12px',
                        background: 'rgba(0,0,0,0.2)',
                        borderRadius: '8px',
                      }}
                    >
                      <span
                        style={{
                          fontSize: '13px',
                          fontWeight: '500',
                          minWidth: '160px',
                          color: '#ccc',
                        }}
                      >
                        {agentId.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                      </span>
                      <input
                        type="text"
                        value={current}
                        onChange={(e) =>
                          setAgentModels({ ...agentModels, [agentId]: e.target.value })
                        }
                        placeholder={defaults[agentId] || 'default'}
                        style={{
                          flex: 1,
                          padding: '8px 12px',
                          borderRadius: '6px',
                          border: isCustom
                            ? '1px solid #ff8844'
                            : '1px solid rgba(255,255,255,0.1)',
                          background: 'rgba(0,0,0,0.3)',
                          color: '#fff',
                          fontSize: '13px',
                          fontFamily: 'monospace',
                        }}
                      />
                      {isCustom && (
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: '600',
                            color: '#ff8844',
                            background: 'rgba(255,136,68,0.1)',
                            padding: '2px 6px',
                            borderRadius: '4px',
                          }}
                        >
                          CUSTOM
                        </span>
                      )}
                      {!isCustom && agentModels[agentId] && (
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: '600',
                            color: '#00ff88',
                            background: 'rgba(0,255,136,0.1)',
                            padding: '2px 6px',
                            borderRadius: '4px',
                          }}
                        >
                          DEFAULT
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
