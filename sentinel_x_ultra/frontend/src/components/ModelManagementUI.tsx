import { useState, useEffect } from 'react';
import { Modal } from './Modal';
import { Button } from './Button';
import { StatusIndicator } from './StatusIndicator';

interface ModelEntry {
  id: string;
  provider: string;
  modelName: string;
  apiEndpoint: string;
  apiKey: string;
  temperature: number;
  contextLength: number;
  priority: number;
  enabled: boolean;
}

interface ProviderOption {
  id: string;
  name: string;
  defaultUrl: string;
  placeholder: string;
  models: string[];
}

const PROVIDERS: ProviderOption[] = [
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
    models: ['openrouter/auto', 'meta-llama/llama-3.3-70b-instruct', 'google/gemini-2.0-flash-exp'],
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
    models: ['llama3.1', 'local'],
  },
  {
    id: 'vllm',
    name: 'vLLM (Local)',
    defaultUrl: 'http://localhost:8000/v1',
    placeholder: 'not-required',
    models: ['llama3.1', 'mixtral', 'qwen2'],
  },
];

const providerColors: Record<string, string> = {
  openai: '#00ff88',
  anthropic: '#ff8844',
  groq: '#aa88ff',
  openrouter: '#00d4ff',
  ollama: '#ffaa00',
  gemini: '#00d4ff',
  mistral: '#00ff88',
  lmstudio: '#aa88ff',
  vllm: '#ff8844',
};

export function ModelManagementUI() {
  const [models, setModels] = useState<ModelEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingModel, setEditingModel] = useState<ModelEntry | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<
    Record<string, { status: 'success' | 'error'; message: string }>
  >({});

  // Form state
  const [formProvider, setFormProvider] = useState('openai');
  const [formModelName, setFormModelName] = useState('gpt-4o');
  const [formApiEndpoint, setFormApiEndpoint] = useState('https://api.openai.com/v1');
  const [formApiKey, setFormApiKey] = useState('');
  const [formTemperature, setFormTemperature] = useState(0.7);
  const [formContextLength, setFormContextLength] = useState(8192);
  const [formPriority, setFormPriority] = useState(1);
  const [formEnabled, setFormEnabled] = useState(true);
  const [formSaving, setFormSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    loadModels();
  }, []);

  const loadModels = async () => {
    setLoading(true);
    try {
      const [configRes, agentRes] = await Promise.all([
        fetch('/api/config/providers'),
        fetch('/api/config/agent-models'),
      ]);
      const configData = await configRes.json();
      const agentData = await agentRes.json();

      const configuredProviders = configData.providers || [];
      const agentModels = agentData.agents || {};
      const agentCategories = agentData.categories || {};

      // Build model entries from configured providers + agent models
      const entries: ModelEntry[] = configuredProviders.map((provider: string, i: number) => ({
        id: `provider-${provider}`,
        provider,
        modelName:
          agentModels[provider] || PROVIDERS.find((p) => p.id === provider)?.models[0] || 'auto',
        apiEndpoint: PROVIDERS.find((p) => p.id === provider)?.defaultUrl || '',
        apiKey: '••••••••',
        temperature: 0.7,
        contextLength: 8192,
        priority: i + 1,
        enabled: true,
      }));

      setModels(entries);
    } catch (e) {
      console.error('Failed to load models:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleProviderChange = (providerId: string) => {
    setFormProvider(providerId);
    const provider = PROVIDERS.find((p) => p.id === providerId);
    if (provider) {
      setFormApiEndpoint(provider.defaultUrl);
      setFormModelName(provider.models[0]);
    }
  };

  const testConnection = async (
    provider: string,
    apiKey: string,
    baseUrl: string,
    modelName: string,
  ) => {
    const testId = `test-${provider}-${Date.now()}`;
    setTestingId(testId);
    setTestResults((prev) => ({ ...prev, [testId]: { status: 'success', message: 'Testing...' } }));

    try {
      const res = await fetch(
        `/api/config/test?provider=${provider}&base_url=${encodeURIComponent(baseUrl)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: apiKey, model: modelName }),
        },
      );
      const data = await res.json();
      if (data.status === 'ok') {
        setTestResults((prev) => ({
          ...prev,
          [testId]: {
            status: 'success',
            message: `✅ Connected! ${data.model || modelName} (${data.latency_ms}ms)`,
          },
        }));
      } else {
        setTestResults((prev) => ({
          ...prev,
          [testId]: { status: 'error', message: `❌ ${data.error || 'Connection failed'}` },
        }));
      }
    } catch (e: any) {
      setTestResults((prev) => ({
        ...prev,
        [testId]: { status: 'error', message: `❌ ${e.message}` },
      }));
    } finally {
      setTestingId(null);
    }
  };

  const saveModel = async () => {
    setFormSaving(true);
    setFormError('');
    try {
      const res = await fetch('/api/config/save-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: formProvider,
          api_key: formApiKey,
          base_url: formApiEndpoint,
        }),
      });
      const data = await res.json();
      if (data.status === 'ok') {
        setShowAddModal(false);
        setEditingModel(null);
        await loadModels();
      } else {
        setFormError(data.error || 'Failed to save');
      }
    } catch (e: any) {
      setFormError(String(e));
    } finally {
      setFormSaving(false);
    }
  };

  const deleteModel = async (provider: string) => {
    // Remove only the specific provider from config
    try {
      // Fetch current agent models
      const currentRes = await fetch('/api/config/agent-models');
      const currentData = await currentRes.json();
      const currentAgents = currentData.agents || {};
      // Remove target provider
      delete currentAgents[provider];
      // Also clear provider key
      await fetch('/api/config/save-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, api_key: '', base_url: '' }),
      });
      // Save updated agent models
      const res = await fetch('/api/config/agent-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agents: currentAgents }),
      });
      if (res.ok) {
        setModels((prev) => prev.filter((m) => m.provider !== provider));
        // Reload to get fresh state
        await loadModels();
      }
    } catch {
      /* ignore */
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '32px', textAlign: 'center', color: '#888' }}>
        <div
          style={{
            width: '32px',
            height: '32px',
            border: '3px solid rgba(0,212,255,0.15)',
            borderTopColor: '#00d4ff',
            borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
            margin: '0 auto 16px',
          }}
        />
        Loading models...
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(0,212,255,0.1), rgba(0,255,136,0.05))',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(0,212,255,0.2)',
          marginBottom: '24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <div>
          <h2
            style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '4px', color: '#00d4ff' }}
          >
            🤖 Model Management
          </h2>
          <p style={{ fontSize: '13px', color: '#888' }}>
            Configure and manage AI models for security analysis agents
          </p>
        </div>
        <Button
          variant="gradient"
          icon="+"
          onClick={() => {
            setShowAddModal(true);
            setFormProvider('openai');
            setFormModelName('gpt-4o');
            setFormApiEndpoint('https://api.openai.com/v1');
            setFormApiKey('');
            setFormEnabled(true);
            setFormError('');
          }}
        >
          Add Model
        </Button>
      </div>

      {/* Model Cards */}
      {models.length === 0 ? (
        <div
          style={{
            textAlign: 'center',
            padding: '80px 40px',
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '16px',
            border: '1px dashed rgba(255,255,255,0.1)',
          }}
        >
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>🤖</div>
          <h3 style={{ fontSize: '18px', marginBottom: '8px' }}>No models configured</h3>
          <p style={{ color: '#666', marginBottom: '24px' }}>
            Add an AI provider to enable security analysis agents
          </p>
          <Button
            variant="gradient"
            onClick={() => {
              setShowAddModal(true);
              setFormProvider('openai');
              setFormModelName('gpt-4o');
            }}
          >
            + Add Your First Model
          </Button>
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
            gap: '16px',
          }}
        >
          {models.map((entry) => {
            const provider = PROVIDERS.find((p) => p.id === entry.provider);
            const color = providerColors[entry.provider] || '#888';
            const testId = `test-${entry.provider}`;
            const testResult = testResults[testId];

            return (
              <div
                key={entry.id}
                style={{
                  background: 'rgba(15,15,26,0.95)',
                  borderRadius: '16px',
                  border: `1px solid ${entry.enabled ? `${color}30` : 'rgba(255,255,255,0.05)'}`,
                  padding: '20px',
                  opacity: entry.enabled ? 1 : 0.5,
                  transition: 'all 0.2s',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    marginBottom: '16px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ fontSize: '28px' }}>🤖</div>
                    <div>
                      <h4 style={{ fontSize: '15px', fontWeight: '600', color }}>
                        {provider?.name || entry.provider}
                      </h4>
                      <div style={{ fontSize: '12px', color: '#888', fontFamily: 'monospace' }}>
                        {entry.modelName}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      onClick={() =>
                        testConnection(
                          entry.provider,
                          entry.apiKey,
                          entry.apiEndpoint,
                          entry.modelName,
                        )
                      }
                      style={{
                        padding: '6px 10px',
                        borderRadius: '6px',
                        border: '1px solid rgba(0,212,255,0.3)',
                        background: 'rgba(0,212,255,0.1)',
                        color: '#00d4ff',
                        cursor: 'pointer',
                        fontSize: '10px',
                        fontWeight: '600',
                      }}
                    >
                      {testingId === testId ? '⏳' : 'Test'}
                    </button>
                    <button
                      onClick={() => deleteModel(entry.provider)}
                      style={{
                        padding: '6px 10px',
                        borderRadius: '6px',
                        border: '1px solid rgba(255,68,68,0.3)',
                        background: 'rgba(255,68,68,0.1)',
                        color: '#ff4444',
                        cursor: 'pointer',
                        fontSize: '10px',
                        fontWeight: '600',
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </div>

                {/* Details */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  <div>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '2px' }}>
                      Endpoint
                    </div>
                    <div
                      style={{
                        fontSize: '11px',
                        color: '#aaa',
                        fontFamily: 'monospace',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {entry.apiEndpoint}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '2px' }}>
                      Status
                    </div>
                    <StatusIndicator
                      status={entry.enabled ? 'online' : 'offline'}
                      label={entry.enabled ? 'Enabled' : 'Disabled'}
                      size="sm"
                    />
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '2px' }}>
                      Temperature
                    </div>
                    <div style={{ fontSize: '12px', color: '#888' }}>{entry.temperature}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '2px' }}>
                      Context
                    </div>
                    <div style={{ fontSize: '12px', color: '#888' }}>
                      {entry.contextLength.toLocaleString()} tokens
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: '#666', marginBottom: '2px' }}>
                      Priority
                    </div>
                    <div style={{ fontSize: '12px', color: '#888' }}>{entry.priority}</div>
                  </div>
                </div>

                {/* Test result */}
                {testResult && (
                  <div
                    style={{
                      marginTop: '12px',
                      padding: '8px 12px',
                      background:
                        testResult.status === 'success'
                          ? 'rgba(0,255,136,0.1)'
                          : 'rgba(255,68,68,0.1)',
                      borderRadius: '6px',
                      fontSize: '11px',
                      color: testResult.status === 'success' ? '#00ff88' : '#ff4444',
                    }}
                  >
                    {testResult.message}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Add/Edit Modal */}
      <Modal
        isOpen={showAddModal}
        onClose={() => {
          setShowAddModal(false);
          setEditingModel(null);
        }}
        title={editingModel ? 'Edit Model' : 'Add Model'}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Provider */}
          <div>
            <label
              style={{
                display: 'block',
                fontSize: '12px',
                color: '#888',
                marginBottom: '4px',
                fontWeight: '600',
              }}
            >
              Provider
            </label>
            <select
              value={formProvider}
              onChange={(e) => handleProviderChange(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                color: '#fff',
                fontSize: '13px',
              }}
            >
              {PROVIDERS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          {/* Model Name */}
          <div>
            <label
              style={{
                display: 'block',
                fontSize: '12px',
                color: '#888',
                marginBottom: '4px',
                fontWeight: '600',
              }}
            >
              Model Name
            </label>
            <input
              type="text"
              value={formModelName}
              onChange={(e) => setFormModelName(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                color: '#00d4ff',
                fontSize: '13px',
                fontFamily: 'monospace',
              }}
              placeholder="gpt-4o"
            />
          </div>

          {/* API Endpoint */}
          <div>
            <label
              style={{
                display: 'block',
                fontSize: '12px',
                color: '#888',
                marginBottom: '4px',
                fontWeight: '600',
              }}
            >
              API Endpoint
            </label>
            <input
              type="text"
              value={formApiEndpoint}
              onChange={(e) => setFormApiEndpoint(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                color: '#fff',
                fontSize: '13px',
                fontFamily: 'monospace',
              }}
              placeholder="https://api.openai.com/v1"
            />
          </div>

          {/* API Key */}
          <div>
            <label
              style={{
                display: 'block',
                fontSize: '12px',
                color: '#888',
                marginBottom: '4px',
                fontWeight: '600',
              }}
            >
              API Key
            </label>
            <input
              type="password"
              value={formApiKey}
              onChange={(e) => setFormApiKey(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                color: '#fff',
                fontSize: '13px',
              }}
              placeholder={
                PROVIDERS.find((p) => p.id === formProvider)?.placeholder || 'Enter API key'
              }
            />
          </div>

          {/* Temperature & Context Length side by side */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '12px',
                  color: '#888',
                  marginBottom: '4px',
                  fontWeight: '600',
                }}
              >
                Temperature
              </label>
              <input
                type="number"
                value={formTemperature}
                onChange={(e) => setFormTemperature(parseFloat(e.target.value))}
                min={0}
                max={2}
                step={0.1}
                style={{
                  width: '100%',
                  padding: '10px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: '#ffaa00',
                  fontSize: '13px',
                }}
              />
            </div>
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '12px',
                  color: '#888',
                  marginBottom: '4px',
                  fontWeight: '600',
                }}
              >
                Context Length
              </label>
              <input
                type="number"
                value={formContextLength}
                onChange={(e) => setFormContextLength(parseInt(e.target.value))}
                min={1024}
                max={128000}
                step={1024}
                style={{
                  width: '100%',
                  padding: '10px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: '#00d4ff',
                  fontSize: '13px',
                }}
              />
            </div>
          </div>

          {/* Priority & Enabled */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '12px',
              alignItems: 'end',
            }}
          >
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '12px',
                  color: '#888',
                  marginBottom: '4px',
                  fontWeight: '600',
                }}
              >
                Priority
              </label>
              <input
                type="number"
                value={formPriority}
                onChange={(e) => setFormPriority(parseInt(e.target.value))}
                min={1}
                max={10}
                style={{
                  width: '100%',
                  padding: '10px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: '#fff',
                  fontSize: '13px',
                }}
              />
            </div>
            <div>
              <label
                style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}
              >
                <input
                  type="checkbox"
                  checked={formEnabled}
                  onChange={(e) => setFormEnabled(e.target.checked)}
                  style={{ accentColor: '#00d4ff' }}
                />
                <span style={{ fontSize: '13px', color: '#888' }}>Enabled</span>
              </label>
            </div>
          </div>

          {/* Test button */}
          <Button
            variant="primary"
            icon="🔍"
            onClick={() => testConnection(formProvider, formApiKey, formApiEndpoint, formModelName)}
            disabled={!formApiKey && formProvider !== 'ollama'}
          >
            Test Connection
          </Button>

          {/* Error */}
          {formError && (
            <div
              style={{
                padding: '10px',
                background: 'rgba(255,68,68,0.1)',
                borderRadius: '8px',
                fontSize: '12px',
                color: '#ff4444',
              }}
            >
              {formError}
            </div>
          )}

          {/* Save */}
          <Button
            variant="gradient"
            onClick={saveModel}
            loading={formSaving}
            disabled={!formApiKey && formProvider !== 'ollama'}
            fullWidth
          >
            {editingModel ? 'Update Model' : 'Add Model'}
          </Button>
        </div>
      </Modal>
    </div>
  );
}
