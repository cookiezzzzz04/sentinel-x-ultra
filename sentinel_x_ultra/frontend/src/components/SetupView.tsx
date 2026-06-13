import { useState, useEffect } from 'react';

export function SetupView({
  configuredProviders,
  onProviderConfigured,
}: {
  configuredProviders: Set<string>;
  onProviderConfigured: (providerId: string) => void;
}) {
  const [selectedProvider, setSelectedProvider] = useState('openai');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [model, setModel] = useState('');
  const [testStatus, setTestStatus] = useState<{
    type: 'none' | 'success' | 'error';
    message: string;
  }>({ type: 'none', message: '' });
  const [saved, setSaved] = useState(false);
  const [isTesting, setIsTesting] = useState(false);

  const providers = [
    {
      id: 'openai',
      name: 'OpenAI',
      defaultUrl: 'https://api.openai.com/v1',
      placeholder: 'sk-...',
      models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo', 'o1', 'o1-mini'],
    },
    {
      id: 'anthropic',
      name: 'Anthropic',
      defaultUrl: 'https://api.anthropic.com',
      placeholder: 'sk-ant-api...',
      models: ['claude-3.5-sonnet-20241022', 'claude-3.5-haiku-20241022', 'claude-3-opus-20240229'],
    },
    {
      id: 'groq',
      name: 'Groq',
      defaultUrl: 'https://api.groq.com/openai/v1',
      placeholder: 'gsk_...',
      models: [
        'llama-3.3-70b-versatile',
        'llama-3.1-70b-versatile',
        'llama-3.1-8b-instant',
        'mixtral-8x7b-32768',
      ],
    },
    {
      id: 'openrouter',
      name: 'OpenRouter',
      defaultUrl: 'https://openrouter.ai/api/v1',
      placeholder: 'sk-or-...',
      models: [
        'openrouter/auto',
        'meta-llama/llama-3.3-70b-instruct',
        'google/gemini-2.0-flash-exp',
      ],
    },
    {
      id: 'ollama',
      name: 'Ollama (Local)',
      defaultUrl: 'http://localhost:11434/v1',
      placeholder: 'not-required',
      models: ['llama3.3', 'llama3.2', 'mistral', 'codellama'],
    },
    {
      id: 'gemini',
      name: 'Google Gemini',
      defaultUrl: 'https://generativelanguage.googleapis.com',
      placeholder: 'AIza...',
      models: ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-2.0-flash-exp'],
    },
    {
      id: 'mistral',
      name: 'Mistral AI',
      defaultUrl: 'https://api.mistral.ai/v1',
      placeholder: '...',
      models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest'],
    },
    {
      id: 'lmstudio',
      name: 'LM Studio (Local)',
      defaultUrl: 'http://localhost:1234/v1',
      placeholder: 'not-required',
      models: ['llama3.1', 'llama3.2', 'mistral', 'codellama'],
    },
    {
      id: 'vllm',
      name: 'vLLM (Local)',
      defaultUrl: 'http://localhost:8000/v1',
      placeholder: 'not-required',
      models: ['llama3.1', 'mixtral', 'qwen2'],
    },
    {
      id: 'opencode',
      name: 'OpenCode (Self-hosted)',
      defaultUrl: 'http://localhost:8080',
      placeholder: 'not-required',
      models: ['auto'],
    },
    {
      id: 'local',
      name: 'Local/Custom',
      defaultUrl: 'http://localhost:11434/v1',
      placeholder: 'not-required',
      models: ['auto'],
    },
  ];

  const currentProvider = providers.find((p) => p.id === selectedProvider) || providers[0];

  const handleProviderChange = (providerId: string) => {
    setSelectedProvider(providerId);
    const provider = providers.find((p) => p.id === providerId);
    if (provider) {
      setBaseUrl(provider.defaultUrl);
      setModel(provider.models[0]);
    }
    setTestStatus({ type: 'none', message: '' });
  };

  const handleSave = async () => {
    try {
      const res = await fetch('/api/config/save-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: selectedProvider, api_key: apiKey, base_url: baseUrl }),
      });
      const data = await res.json();
      if (data.status === 'ok') {
        setSaved(true);
        onProviderConfigured(selectedProvider);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch (e) {
      console.error('Failed to save API key:', e);
    }
  };

  const handleTest = async () => {
    if (!apiKey && selectedProvider !== 'ollama') {
      setTestStatus({ type: 'error', message: 'Please enter an API key' });
      return;
    }
    setIsTesting(true);
    setTestStatus({ type: 'none', message: '' });
    try {
      const res = await fetch(
        '/api/config/test?' +
          new URLSearchParams({ provider: selectedProvider, base_url: baseUrl }),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: apiKey, model: model }),
        },
      );
      if (!res.ok) {
        const text = await res.text();
        setTestStatus({
          type: 'error',
          message: `❌ HTTP ${res.status}: ${text.substring(0, 200)}`,
        });
        return;
      }
      const data = await res.json();
      if (data.status === 'ok') {
        setTestStatus({
          type: 'success',
          message: `✅ Connected! Model: ${data.model || model}, Latency: ${Math.round(data.latency_ms)}ms`,
        });
      } else {
        setTestStatus({ type: 'error', message: `❌ ${data.error}` });
      }
    } catch (e) {
      setTestStatus({ type: 'error', message: `❌ Failed: ${e}` });
    } finally {
      setIsTesting(false);
    }
  };

  useEffect(() => {
    setTimeout(() => handleProviderChange('openai'), 0);
  }, []);

  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px' }}>⚙️ Settings</h2>
      <p style={{ color: '#666', marginBottom: '32px' }}>
        Configure your LLM provider to enable AI-powered security analysis
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '16px',
            padding: '24px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '20px' }}>
            Provider Configuration
          </h3>
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}
            >
              Provider
            </label>
            <select
              value={selectedProvider}
              onChange={(e) => handleProviderChange(e.target.value)}
              style={{
                width: '100%',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px',
              }}
            >
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}
            >
              Model
            </label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              style={{
                width: '100%',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                padding: '12px',
                color: '#00d4ff',
                fontSize: '14px',
                fontFamily: 'monospace',
              }}
            >
              {currentProvider.models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}
            >
              API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={currentProvider.placeholder}
              style={{
                width: '100%',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px',
              }}
            />
          </div>
          <div style={{ marginBottom: '24px' }}>
            <label
              style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}
            >
              Base URL
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              style={{
                width: '100%',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px',
                fontFamily: 'monospace',
              }}
            />
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={handleTest}
              disabled={isTesting || (!apiKey && selectedProvider !== 'ollama')}
              style={{
                flex: 1,
                background: 'rgba(0, 212, 255, 0.1)',
                color: apiKey || selectedProvider === 'ollama' ? '#00d4ff' : '#666',
                border: '1px solid #00d4ff',
                borderRadius: '8px',
                padding: '12px',
                cursor: apiKey || selectedProvider === 'ollama' ? 'pointer' : 'not-allowed',
                fontSize: '13px',
                fontWeight: '600',
              }}
            >
              {isTesting ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              onClick={handleSave}
              disabled={!apiKey && selectedProvider !== 'ollama'}
              style={{
                flex: 1,
                background: saved ? '#00ff88' : 'linear-gradient(135deg, #00d4ff, #00ff88)',
                color: '#000',
                border: 'none',
                borderRadius: '8px',
                padding: '12px',
                fontWeight: '700',
                cursor: apiKey || selectedProvider === 'ollama' ? 'pointer' : 'not-allowed',
                fontSize: '13px',
              }}
            >
              {saved ? '✓ Saved!' : 'Save'}
            </button>
          </div>
          {testStatus.message && (
            <div
              style={{
                marginTop: '16px',
                padding: '12px',
                background:
                  testStatus.type === 'success'
                    ? 'rgba(0, 255, 136, 0.1)'
                    : 'rgba(255, 68, 68, 0.1)',
                borderRadius: '8px',
                fontSize: '13px',
                border: `1px solid ${testStatus.type === 'success' ? '#00ff88' : '#ff4444'}`,
              }}
            >
              {testStatus.message}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div
            style={{
              background: 'rgba(15, 15, 26, 0.95)',
              borderRadius: '16px',
              padding: '24px',
              border: '1px solid rgba(255,255,255,0.05)',
            }}
          >
            <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
              Configured Providers
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {providers.map((p) => {
                const isConfigured = configuredProviders.has(p.id);
                return (
                  <div
                    key={p.id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '12px',
                      background:
                        selectedProvider === p.id ? 'rgba(0, 212, 255, 0.1)' : 'rgba(0,0,0,0.2)',
                      borderRadius: '8px',
                      border:
                        selectedProvider === p.id ? '1px solid #00d4ff' : '1px solid transparent',
                      cursor: 'pointer',
                    }}
                    onClick={() => setSelectedProvider(p.id)}
                  >
                    <span style={{ fontWeight: '500' }}>{p.name}</span>
                    {isConfigured ? (
                      <span style={{ fontSize: '11px', color: '#00ff88' }}>● Configured</span>
                    ) : (
                      <span style={{ fontSize: '11px', color: '#666' }}>○ Not configured</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          <div
            style={{
              background:
                'linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(0, 255, 136, 0.05))',
              borderRadius: '16px',
              padding: '24px',
              border: '1px solid rgba(0, 212, 255, 0.2)',
            }}
          >
            <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>💡 Tips</h3>
            <ul
              style={{ fontSize: '12px', color: '#888', listStyle: 'none', padding: 0, margin: 0 }}
            >
              <li style={{ marginBottom: '8px' }}>• Groq offers free tier with llama-3.1 models</li>
              <li style={{ marginBottom: '8px' }}>• OpenRouter provides access to 100+ models</li>
              <li style={{ marginBottom: '8px' }}>• Ollama runs locally - no API key needed</li>
              <li>• API keys are stored in memory only</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
