import { useState, useEffect } from 'react'

interface Project {
  project_id: string
  name: string
  created_at: string
  findings_count?: number
}

interface HealthStatus {
  status: string
  version: string
  providers: string[]
}

// Per-agent model configuration
interface AgentModelConfig {
  [agentId: string]: string
}

// ProviderModels - for future use when we add per-project provider configs
// interface ProviderModels {
//   [key: string]: string[]
// }

function App() {
  const [view, setView] = useState<'dashboard' | 'models' | 'settings'>('dashboard')
  const [projects, setProjects] = useState<Project[]>([])
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [currentProject, setCurrentProject] = useState<Project | null>(null)
  const [configuredProviders, setConfiguredProviders] = useState<Set<string>>(new Set())

  useEffect(() => {
    fetchHealth()
    fetchProjects()
    fetchConfiguredProviders()
  }, [])

  const fetchConfiguredProviders = async () => {
    try {
      const res = await fetch('/api/config/providers')
      const data = await res.json()
      if (data.providers) {
        setConfiguredProviders(new Set(data.providers))
      }
    } catch (e) {
      console.error('Failed to fetch configured providers:', e)
    }
  }

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health')
      const data = await res.json()
      setHealth(data)
    } catch (e) {
      console.error('Failed to fetch health:', e)
    }
  }

  const fetchProjects = async () => {
    try {
      const res = await fetch('/api/projects')
      const data = await res.json()
      setProjects(data.projects || [])
    } catch (e) {
      console.error('Failed to fetch projects:', e)
    } finally {
      setLoading(false)
    }
  }

  const createProject = async (name: string) => {
    try {
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      })
      const data = await res.json()
      const newProject = { project_id: data.project_id, name: data.name, created_at: new Date().toISOString() }
      setProjects([...projects, newProject])
    } catch (e) {
      console.error('Failed to create project:', e)
    }
  }

  const deleteProject = async (projectId: string) => {
    if (!confirm('Are you sure you want to delete this project? This cannot be undone.')) return
    try {
      await fetch(`/api/projects/${projectId}`, { method: 'DELETE' })
      setProjects(projects.filter(p => p.project_id !== projectId))
      if (currentProject?.project_id === projectId) {
        setCurrentProject(null)
        setView('dashboard')
      }
    } catch (e) {
      console.error('Failed to delete project:', e)
    }
  }

  const openProject = async (project: Project) => {
    setCurrentProject(project)
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0a0a0f', color: '#fff' }}>
      {/* Header */}
      <header style={{
        padding: '16px 32px',
        borderBottom: '1px solid #1a1a2e',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'linear-gradient(180deg, #0f0f1a 0%, #0a0a0f 100%)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '24px' }}>🛡️</span>
            <h1 style={{ fontSize: '20px', fontWeight: 'bold', background: 'linear-gradient(90deg, #00d4ff, #00ff88)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              SENTINEL-X ULTRA
            </h1>
          </div>
          <span style={{ fontSize: '11px', color: '#666', background: '#1a1a2e', padding: '4px 8px', borderRadius: '4px' }}>
            v0.2.0
          </span>
        </div>
        <nav style={{ display: 'flex', gap: '8px' }}>
          <NavButton active={view === 'dashboard' && !currentProject} onClick={() => { setView('dashboard'); setCurrentProject(null) }}>
            📊 Dashboard
          </NavButton>
          <NavButton active={view === 'models'} onClick={() => setView('models')}>
            🤖 Models
          </NavButton>
          <NavButton active={view === 'settings'} onClick={() => setView('settings')}>
            ⚙️ Settings
          </NavButton>
        </nav>
      </header>

      {/* Main Content */}
      <main style={{ padding: '32px', maxWidth: '1400px', margin: '0 auto' }}>
        {loading ? (
          <LoadingSpinner />
        ) : currentProject ? (
          <ProjectView project={currentProject} onBack={() => { setCurrentProject(null); setView('dashboard') }} />
        ) : view === 'settings' ? (
          <SetupView configuredProviders={configuredProviders} onProviderConfigured={(providerId) => {
            setConfiguredProviders(prev => new Set([...prev, providerId]))
          }} />
        ) : view === 'dashboard' ? (
          <Dashboard projects={projects} onCreateProject={createProject} onDeleteProject={deleteProject} onOpenProject={openProject} />
        ) : view === 'models' ? (
          <ModelConfigView configuredProviders={configuredProviders} />
        ) : null}
      </main>

      {/* Footer */}
      <footer style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        padding: '12px 32px',
        borderTop: '1px solid #1a1a2e',
        display: 'flex',
        justifyContent: 'space-between',
        fontSize: '12px',
        color: '#666',
        background: '#0a0a0f'
      }}>
        <span>System: {health?.status === 'ok' ? '🟢 Online' : '🔴 Offline'}</span>
        <span>{health?.providers?.length || 0} providers • {projects.length} projects</span>
      </footer>
    </div>
  )
}

function NavButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: active ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
        border: '1px solid',
        borderColor: active ? '#00d4ff' : '#2a2a3e',
        color: active ? '#00d4ff' : '#888',
        fontSize: '13px',
        cursor: 'pointer',
        padding: '8px 16px',
        borderRadius: '6px',
        transition: 'all 0.2s',
        display: 'flex',
        alignItems: 'center',
        gap: '6px'
      }}
    >
      {children}
    </button>
  )
}

// ============ PROJECT VIEW ============
function ProjectView({ project, onBack }: { project: Project; onBack: () => void }) {
  const [activeTab, setActiveTab] = useState<'overview' | 'analysis' | 'agents' | 'findings'>('overview')
  const [agentOutput, setAgentOutput] = useState<string>('')
  const [runningAgent, setRunningAgent] = useState<string | null>(null)
  
  const runAgent = async (agentType: string, action: string, inputData: any) => {
    setRunningAgent(agentType)
    setAgentOutput('Running agent...')
    try {
      const res = await fetch(`/api/projects/${project.project_id}/agents/${agentType}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, input_data: inputData }),
      })
      const data = await res.json()
      setAgentOutput(JSON.stringify(data, null, 2))
    } catch (e) {
      setAgentOutput(`Error: ${e}`)
    } finally {
      setRunningAgent(null)
    }
  }
  
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>
        <button onClick={onBack} style={{
          background: '#1a1a2e',
          border: '1px solid #2a2a3e',
          color: '#888',
          padding: '8px 16px',
          borderRadius: '6px',
          cursor: 'pointer',
          fontSize: '13px'
        }}>
          ← Back
        </button>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold' }}>{project.name}</h1>
          <p style={{ fontSize: '12px', color: '#666' }}>Project ID: {project.project_id}</p>
        </div>
      </div>
      
      <div style={{ display: 'flex', gap: '8px', marginBottom: '24px', borderBottom: '1px solid #1a1a2e', paddingBottom: '16px' }}>
        {['overview', 'analysis', 'agents', 'findings'].map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab as any)}
            style={{
              background: activeTab === tab ? '#00d4ff' : '#1a1a2e',
              color: activeTab === tab ? '#000' : '#888',
              border: 'none',
              padding: '10px 20px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontWeight: '600',
              textTransform: 'capitalize'
            }}>
            {tab}
          </button>
        ))}
      </div>
      
      {activeTab === 'agents' ? (
        <AgentsPanel runningAgent={runningAgent} onRunAgent={runAgent} output={agentOutput} />
      ) : activeTab === 'overview' ? (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>
            <StatCard label="Findings" value="0" icon="🔍" />
            <StatCard label="Critical" value="0" icon="🚨" />
            <StatCard label="High" value="0" icon="⚠️" />
            <StatCard label="Medium" value="0" icon="📋" />
          </div>
          
          <div style={{ background: '#12121a', borderRadius: '12px', padding: '32px', border: '1px solid #1a1a2e' }}>
            <h3 style={{ fontSize: '16px', marginBottom: '16px' }}>Quick Actions</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
              <ActionCard title="Upload Code" description="Upload source code for SAST analysis" icon="📁" />
              <ActionCard title="Scan Website" description="Analyze a web application for vulnerabilities" icon="🌐" />
              <ActionCard title="Import Scope" description="Import bug bounty scope file" icon="📋" />
            </div>
          </div>
        </>
      ) : activeTab === 'analysis' ? (
        <AnalysisPanel projectId={project.project_id} />
      ) : (
        <div style={{ padding: '40px', textAlign: 'center', color: '#666' }}>
          No findings yet. Run agents to discover vulnerabilities.
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, icon }: { label: string; value: string; icon: string }) {
  return (
    <div style={{ background: '#12121a', borderRadius: '12px', padding: '20px', border: '1px solid #1a1a2e', textAlign: 'center' }}>
      <div style={{ fontSize: '24px', marginBottom: '8px' }}>{icon}</div>
      <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#00d4ff' }}>{value}</div>
      <div style={{ fontSize: '12px', color: '#666' }}>{label}</div>
    </div>
  )
}

function ActionCard({ title, description, icon }: { title: string; description: string; icon: string }) {
  return (
    <div style={{
      background: '#1a1a2e',
      borderRadius: '8px',
      padding: '20px',
      cursor: 'pointer',
      transition: 'all 0.2s',
      border: '1px solid #2a2a3e'
    }}>
      <div style={{ fontSize: '28px', marginBottom: '12px' }}>{icon}</div>
      <h4 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px' }}>{title}</h4>
      <p style={{ fontSize: '12px', color: '#666' }}>{description}</p>
    </div>
  )
}

// ============ DASHBOARD ============
function Dashboard({ projects, onCreateProject, onDeleteProject, onOpenProject }: { 
  projects: Project[]; 
  onCreateProject: (name: string) => void;
  onDeleteProject: (id: string) => void;
  onOpenProject: (project: Project) => void;
}) {
  const [newProjectName, setNewProjectName] = useState('')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null)

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault()
    if (newProjectName.trim()) {
      onCreateProject(newProjectName.trim())
      setNewProjectName('')
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '28px', fontWeight: 'bold', marginBottom: '8px' }}>Dashboard</h2>
          <p style={{ color: '#666' }}>Manage your security analysis projects</p>
        </div>
        <form onSubmit={handleCreate} style={{ display: 'flex', gap: '12px' }}>
          <input
            type="text"
            value={newProjectName}
            onChange={(e) => setNewProjectName(e.target.value)}
            placeholder="Enter project name..."
            style={{
              background: '#1a1a2e',
              border: '1px solid #2a2a3e',
              borderRadius: '8px',
              padding: '12px 16px',
              color: '#fff',
              width: '280px',
              fontSize: '14px'
            }}
          />
          <button
            type="submit"
            style={{
              background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
              color: '#000',
              border: 'none',
              borderRadius: '8px',
              padding: '12px 24px',
              fontWeight: '700',
              cursor: 'pointer',
              fontSize: '14px'
            }}
          >
            + New Project
          </button>
        </form>
      </div>

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>
        <div style={{ background: 'linear-gradient(135deg, #1a1a2e, #12121a)', borderRadius: '12px', padding: '20px', border: '1px solid #2a2a3e' }}>
          <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>Total Projects</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold' }}>{projects.length}</div>
        </div>
        <div style={{ background: 'linear-gradient(135deg, #1a1a2e, #12121a)', borderRadius: '12px', padding: '20px', border: '1px solid #2a2a3e' }}>
          <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>Total Findings</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#00d4ff' }}>0</div>
        </div>
        <div style={{ background: 'linear-gradient(135deg, #1a1a2e, #12121a)', borderRadius: '12px', padding: '20px', border: '1px solid #2a2a3e' }}>
          <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>Critical Issues</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#ff4444' }}>0</div>
        </div>
        <div style={{ background: 'linear-gradient(135deg, #1a1a2e, #12121a)', borderRadius: '12px', padding: '20px', border: '1px solid #2a2a3e' }}>
          <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>Active Providers</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#00ff88' }}>0</div>
        </div>
      </div>

      {/* Projects Grid */}
      {projects.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '80px 40px', background: '#12121a', borderRadius: '16px', border: '1px dashed #2a2a3e' }}>
          <div style={{ fontSize: '64px', marginBottom: '16px' }}>🎯</div>
          <h3 style={{ fontSize: '20px', marginBottom: '8px' }}>No projects yet</h3>
          <p style={{ color: '#666', marginBottom: '24px' }}>Create your first project to start security analysis</p>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <button onClick={() => document.querySelector<HTMLInputElement>('input[placeholder="Enter project name..."]')?.focus()} style={{
              background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
              color: '#000',
              border: 'none',
              borderRadius: '8px',
              padding: '12px 24px',
              fontWeight: '600',
              cursor: 'pointer'
            }}>
              Create Project
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '20px' }}>
          {projects.map((project) => (
            <div key={project.project_id} style={{
              background: '#12121a',
              border: '1px solid #1a1a2e',
              borderRadius: '12px',
              padding: '20px',
              transition: 'all 0.2s',
              cursor: 'pointer',
              position: 'relative'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <h3 style={{ fontSize: '18px', fontWeight: '600' }}>{project.name}</h3>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button onClick={(e) => { e.stopPropagation(); onOpenProject(project) }} style={{
                    background: '#1a1a2e',
                    border: 'none',
                    color: '#00d4ff',
                    padding: '6px 12px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '12px'
                  }}>
                    Open
                  </button>
                  <button onClick={(e) => { e.stopPropagation(); setShowDeleteConfirm(project.project_id) }} style={{
                    background: '#1a1a2e',
                    border: 'none',
                    color: '#ff4444',
                    padding: '6px 12px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '12px'
                  }}>
                    Delete
                  </button>
                </div>
              </div>
              <p style={{ fontSize: '12px', color: '#666', marginBottom: '16px' }}>
                Created {new Date(project.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
              </p>
              <div style={{ display: 'flex', gap: '8px' }}>
                <span style={{ fontSize: '11px', background: '#1a1a2e', color: '#888', padding: '4px 8px', borderRadius: '4px' }}>0 findings</span>
                <span style={{ fontSize: '11px', background: '#1a1a2e', color: '#4ade80', padding: '4px 8px', borderRadius: '4px' }}>● Ready</span>
              </div>
              
              {/* Delete Confirmation Modal */}
              {showDeleteConfirm === project.project_id && (
                <div style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0,0,0,0.9)',
                  borderRadius: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '12px'
                }}>
                  <p style={{ fontSize: '14px', fontWeight: '600' }}>Delete "{project.name}"?</p>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button onClick={(e) => { e.stopPropagation(); onDeleteProject(project.project_id); setShowDeleteConfirm(null) }} style={{
                      background: '#ff4444',
                      color: '#fff',
                      border: 'none',
                      padding: '8px 16px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}>
                      Confirm
                    </button>
                    <button onClick={(e) => { e.stopPropagation(); setShowDeleteConfirm(null) }} style={{
                      background: '#1a1a2e',
                      color: '#888',
                      border: '1px solid #2a2a3e',
                      padding: '8px 16px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}>
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ============ SETUP VIEW ============
function SetupView({ configuredProviders, onProviderConfigured }: { 
  configuredProviders: Set<string>;
  onProviderConfigured: (providerId: string) => void;
}) {
  const [selectedProvider, setSelectedProvider] = useState('openai')
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [model, setModel] = useState('')
  const [testStatus, setTestStatus] = useState<{type: 'none' | 'success' | 'error', message: string}>({type: 'none', message: ''})
  const [saved, setSaved] = useState(false)
  const [isTesting, setIsTesting] = useState(false)

  const providers = [
    { id: 'openai', name: 'OpenAI', defaultUrl: 'https://api.openai.com/v1', placeholder: 'sk-...', models: ['gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-4o', 'gpt-4o-mini', 'gpt-4o-mini-2024-07-18', 'gpt-4-turbo', 'gpt-4-turbo-2024-04-09', 'gpt-4', 'gpt-4-0613', 'gpt-4-32k', 'gpt-4-32k-0613', 'gpt-3.5-turbo', 'gpt-3.5-turbo-16k', 'gpt-3.5-turbo-0613', 'o1', 'o1-mini', 'o1-preview', 'o3-mini', 'o3'] },
    { id: 'anthropic', name: 'Anthropic', defaultUrl: 'https://api.anthropic.com', placeholder: 'sk-ant-api...', models: [
      'claude-fable-5', 'claude-mythos-5', 'claude-opus-4.8', 'claude-sonnet-4.6', 'claude-haiku-4.5',
      'claude-3.5-opus', 'claude-3.5-sonnet-20241022', 'claude-3.5-sonnet-20240620', 'claude-3.5-haiku-20241022',
      'claude-3-opus-20240229', 'claude-3-sonnet-20240229', 'claude-3-haiku-20240307',
      'claude-2.1', 'claude-2.0', 'claude-instant-1.2'
    ] },
    { id: 'groq', name: 'Groq', defaultUrl: 'https://api.groq.com/openai/v1', placeholder: 'gsk_...', models: ['llama-3.3-70b-versatile', 'llama-3.1-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768', 'gemma2-9b-it', 'whisper-large-v3', 'whisper-large-v3-turbo', 'groq/compound', 'groq/compound-mini', 'meta-llama/llama-4-scout-17b-16e-instruct', 'qwen/qwen3-32b', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'openai/gpt-oss-safeguard-20b', 'meta-llama/llama-prompt-guard-2-86m'] },
    { id: 'openrouter', name: 'OpenRouter', defaultUrl: 'https://openrouter.ai/api/v1', placeholder: 'sk-or-...', models: [
      // Special OpenRouter models
      'openrouter/auto', 'openrouter/free',
      // Meta LLama models (most reliable on OpenRouter)
      'meta-llama/llama-3.3-70b-instruct', 'meta-llama/llama-3.1-8b-instant', 'meta-llama/llama-3.1-70b-instruct',
      // Google models
      'google/gemini-2.0-flash-exp', 'google/gemini-2.0-flash',
      // Anthropic models (via OpenRouter)
      'anthropic/claude-3.5-sonnet', 'anthropic/claude-3.5-sonnet-20240620',
      // Mistral models
      'mistralai/mistral-small', 'mistralai/mistral-medium',
      // DeepSeek models
      'deepseek/deepseek-chat', 'deepseek/deepseek-coder',
      // Qwen models
      'qwen/qwen2.5-72b-instruct', 'qwen/qwen2.5-coder-32b',
      // Other popular models
      'cohere/command-r-plus', 'cohere/command-r',
      'x-ai/grok-2', 'x-ai/grok-2-mini',
      'perplexity/sonar', 'perplexity/sonar-pro',
      'microsoft/phi-4', 'snowflake/snowflake-arctic-instruct',
      'databricks/dbrx-instruct',
    ] },
    { id: 'ollama', name: 'Ollama (Local)', defaultUrl: 'http://localhost:11434/v1', placeholder: 'not-required', models: ['llama3.3', 'llama3.2', 'llama3.2-vision', 'llama3.1', 'llama3', 'llama2', 'codellama', 'codellama2', 'mistral', 'mistral-nemo', 'mixtral', 'phi3', 'phi3.5', 'phi4', 'gemma2', 'gemma2:27b', 'gemma', 'qwen2.5', 'qwen2.5-coder', 'qwen2.5-math', 'yi', 'yi-coder', 'yi2', 'deepseek-coder', 'deepseek-llm', 'command-r', 'command-r7b', 'llava', 'llava-llama3', 'bakllava', 'nomic-embed-text', 'all-minimum', 'shawj/neural-chat', 'zephyr', 'embd-01', 'eagle', 'fastchat', 'orca2', 'vicuna'] },
    { id: 'lmstudio', name: 'LM Studio', defaultUrl: 'http://localhost:1234/v1', placeholder: 'not-required', models: ['auto', 'llama3.3', 'llama3.2', 'llama3.2-vision', 'llama3.1', 'llama3', 'llama2', 'codellama', 'codellama2', 'mistral', 'mistral-nemo', 'mixtral', 'phi3', 'phi4', 'gemma2', 'qwen2.5', 'qwen2.5-coder', 'yi', 'yi2', 'deepseek-coder', 'deepseek-llm', 'command-r', 'stablelm', 'smollm', 'gemma2:27b', 'qwen2.5-math'] },
    { id: 'vllm', name: 'vLLM', defaultUrl: 'http://localhost:8000/v1', placeholder: 'not-required', models: ['auto', 'llama3.3', 'llama3.2', 'llama3.2-vision', 'llama3.1', 'llama3', 'llama2', 'codellama', 'mistral', 'mistral-nemo', 'mixtral', 'phi3', 'phi4', 'qwen2.5', 'qwen2.5-coder', 'yi', 'yi2', 'deepseek-llm', 'gemma2', 'command-r'] },
    { id: 'gemini', name: 'Google Gemini', defaultUrl: 'https://generativelanguage.googleapis.com', placeholder: 'AIza...', models: [
      'gemini-3.5-pro', 'gemini-3.5-flash', 'gemini-spark', 'gemini-omni',
      'gemini-3.1-pro', 'gemini-3.1-flash-lite', 'gemini-3-flash', 'gemini-3-ultra',
      'gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.5-flash-lite',
      'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-nano'
    ] },
    { id: 'mistral', name: 'Mistral AI', defaultUrl: 'https://api.mistral.ai/v1', placeholder: '...', models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest', 'mistral-nemo', 'mistral-hoder', 'codestral', 'codestral-latest', 'mistral-embed', 'open-mistral-7b', 'open-mixtral-8x7b', 'open-mixtral-8x22b'] },
    { id: 'opencode', name: 'OpenCode', defaultUrl: 'http://localhost:8080/v1', placeholder: 'not-required', models: [
      'big-pickle', 'stealth',
      'claude-fable-5', 'claude-haiku-4.5', 'claude-opus-4.1', 'claude-opus-4.5', 'claude-opus-4.6', 'claude-opus-4.7', 'claude-opus-4.8', 'claude-sonnet-4', 'claude-sonnet-4.5', 'claude-sonnet-4.6',
      'gpt-5', 'gpt-5-codex', 'gpt-5-nano', 'gpt-5.1', 'gpt-5.1-codex', 'gpt-5.1-codex-max', 'gpt-5.1-codex-mini', 'gpt-5.2', 'gpt-5.2-codex', 'gpt-5.3-codex', 'gpt-5.3-codex-spark', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.4-nano', 'gpt-5.4-pro', 'gpt-5.5', 'gpt-5.5-pro',
      'gemini-3-flash', 'gemini-3.1-pro', 'gemini-3.5-flash',
      'deepseek-v4-flash', 'deepseek-v4-flash-free', 'deepseek-v4-pro',
      'glm-5', 'glm-5.1',
      'kimi-k2.5', 'kimi-k2.6',
      'qwen3.5-plus', 'qwen3.6-plus', 'qwen3.6-plus-free', 'qwen3.7-plus', 'qwen3.7-max',
      'grok-build-0.1',
      'minimax-m2.5', 'minimax-m2.7', 'minimax-m3-free', 'minimax-m3',
      'mimo-v2.5-pro', 'mimo-v2.5-free',
      'nemotron-3-ultra-free',
      'north-mini-code-free'
    ] },
  ]

  const currentProvider = providers.find(p => p.id === selectedProvider) || providers[0]

  const handleProviderChange = (providerId: string) => {
    setSelectedProvider(providerId)
    const provider = providers.find(p => p.id === providerId)
    if (provider) {
      setBaseUrl(provider.defaultUrl)
      setModel(provider.models[0])
    }
    setTestStatus({type: 'none', message: ''})
  }

  const handleSave = async () => {
    try {
      const res = await fetch('/api/config/save-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          api_key: apiKey,
          base_url: baseUrl
        }),
      })
      const data = await res.json()
      if (data.status === 'ok') {
        setSaved(true)
        onProviderConfigured(selectedProvider)
        setTimeout(() => setSaved(false), 2000)
      }
    } catch (e) {
      console.error('Failed to save API key:', e)
    }
  }

  const handleTest = async () => {
    if (!apiKey) {
      setTestStatus({type: 'error', message: 'Please enter an API key'})
      return
    }
    
    // Validate URL to catch common typos
    const normalizedUrl = baseUrl.toLowerCase().trim()
    // Check for .co typo (must be EXACT match of api.groq.co domain, not just any .co substring)
    if (normalizedUrl === 'https://api.groq.co' || normalizedUrl === 'https://api.groq.co/' || 
        normalizedUrl.startsWith('https://api.groq.co/')) {
      setTestStatus({type: 'error', message: '❌ Invalid URL: Groq uses api.groq.com (with .com, not .co)'})
      return
    }
    if (normalizedUrl === 'https://api.groq.ai' || normalizedUrl === 'https://api.groq.ai/' || 
        normalizedUrl.startsWith('https://api.groq.ai/')) {
      setTestStatus({type: 'error', message: '❌ Invalid URL: Groq uses api.groq.com (not .ai)'})
      return
    }
    
    setIsTesting(true)
    setTestStatus({type: 'none', message: ''})
    try {
      const res = await fetch('/api/config/test?' + new URLSearchParams({
        provider: selectedProvider,
        base_url: baseUrl,
      }), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey, model: model }),
      })
      
      // Check response status
      if (!res.ok) {
        const text = await res.text()
        setTestStatus({type: 'error', message: `❌ HTTP ${res.status}: ${text.substring(0, 200)}`})
        return
      }
      
      const data = await res.json()
      if (data.status === 'ok') {
        setTestStatus({type: 'success', message: `✅ Connected successfully! Model: ${data.model || model}, Latency: ${Math.round(data.latency_ms)}ms`})
      } else {
        setTestStatus({type: 'error', message: `❌ ${data.error}`})
      }
    } catch (e) {
      setTestStatus({type: 'error', message: `❌ Failed to connect: ${e}`})
    } finally {
      setIsTesting(false)
    }
  }

  useEffect(() => {
    handleProviderChange('openai')
  }, [])

  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px' }}>⚙️ Settings</h2>
      <p style={{ color: '#666', marginBottom: '32px' }}>Configure your LLM provider to enable AI-powered security analysis</p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
        {/* Left Column - Provider Config */}
        <div style={{ background: '#12121a', borderRadius: '16px', padding: '24px', border: '1px solid #1a1a2e' }}>
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '20px' }}>Provider Configuration</h3>
          
          {/* Provider Selection */}
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Provider</label>
            <select
              value={selectedProvider}
              onChange={(e) => handleProviderChange(e.target.value)}
              style={{
                width: '100%',
                background: '#1a1a2e',
                border: '1px solid #2a2a3e',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px'
              }}
            >
              {providers.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>

          {/* Model Selection */}
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Model</label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              style={{
                width: '100%',
                background: '#1a1a2e',
                border: '1px solid #2a2a3e',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px'
              }}
            >
              {currentProvider.models.map(m => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
            <p style={{ fontSize: '11px', color: '#666', marginTop: '4px' }}>Select the model to use with this provider</p>
          </div>

          {/* API Key */}
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={currentProvider.placeholder}
              style={{
                width: '100%',
                background: '#1a1a2e',
                border: '1px solid #2a2a3e',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px'
              }}
            />
          </div>

          {/* Base URL */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Base URL</label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              style={{
                width: '100%',
                background: '#1a1a2e',
                border: '1px solid #2a2a3e',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px'
              }}
            />
          </div>

          {/* Buttons */}
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={handleTest}
              disabled={isTesting || !apiKey}
              style={{
                background: '#1a1a2e',
                color: apiKey ? '#00d4ff' : '#666',
                border: '1px solid #00d4ff',
                borderRadius: '8px',
                padding: '12px 20px',
                cursor: apiKey ? 'pointer' : 'not-allowed',
                fontSize: '13px',
                fontWeight: '600'
              }}
            >
              {isTesting ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              onClick={handleSave}
              disabled={!apiKey}
              style={{
                background: saved ? '#00ff88' : 'linear-gradient(135deg, #00d4ff, #00ff88)',
                color: '#000',
                border: 'none',
                borderRadius: '8px',
                padding: '12px 20px',
                fontWeight: '700',
                cursor: apiKey ? 'pointer' : 'not-allowed',
                fontSize: '13px'
              }}
            >
              {saved ? '✓ Saved!' : 'Save'}
            </button>
          </div>

          {/* Status Message */}
          {testStatus.message && (
            <div style={{
              marginTop: '16px',
              padding: '12px',
              background: testStatus.type === 'success' ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 68, 68, 0.1)',
              borderRadius: '8px',
              fontSize: '13px',
              border: `1px solid ${testStatus.type === 'success' ? '#00ff88' : '#ff4444'}`
            }}>
              {testStatus.message}
            </div>
          )}
        </div>

        {/* Right Column - Provider Info */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ background: '#12121a', borderRadius: '16px', padding: '24px', border: '1px solid #1a1a2e' }}>
            <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Available Providers</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {providers.map(p => {
                const isConfigured = configuredProviders.has(p.id)
                return (
                  <div key={p.id} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '12px',
                    background: selectedProvider === p.id ? 'rgba(0, 212, 255, 0.1)' : '#1a1a2e',
                    borderRadius: '8px',
                    border: selectedProvider === p.id ? '1px solid #00d4ff' : '1px solid transparent',
                    opacity: isConfigured ? 1 : 0.5,
                    cursor: isConfigured ? 'pointer' : 'not-allowed'
                  }}
                  onClick={() => isConfigured && setSelectedProvider(p.id)}
                  >
                    <span style={{ fontWeight: '500' }}>{p.name}</span>
                    {isConfigured ? (
                      <span style={{ fontSize: '11px', color: '#4ade80' }}>● Configured</span>
                    ) : (
                      <span style={{ fontSize: '11px', color: '#666' }}>○ Not configured</span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          <div style={{ background: 'linear-gradient(135deg, #1a1a2e, #12121a)', borderRadius: '16px', padding: '24px', border: '1px solid #2a2a3e' }}>
            <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>💡 Tips</h3>
            <ul style={{ fontSize: '12px', color: '#888', listStyle: 'none', padding: 0, margin: 0 }}>
              <li style={{ marginBottom: '8px' }}>• Groq offers free tier with llama-3.1 models</li>
              <li style={{ marginBottom: '8px' }}>• OpenRouter provides access to 100+ models</li>
              <li style={{ marginBottom: '8px' }}>• Local providers (Ollama, LM Studio) need running servers</li>
              <li>• API keys are stored in memory only, never saved to disk</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

// ============ MODEL CONFIG VIEW ============
function ModelConfigView({ configuredProviders }: { configuredProviders: Set<string> }) {
  // Per-agent model configuration - each agent has its own model
  const [agentConfigs, setAgentConfigs] = useState<AgentModelConfig>({
    'recon': 'claude-3-5-sonnet-20241022',
    'code-review': 'claude-3-5-sonnet-20241022',
    'threat-modeling': 'claude-3-5-sonnet-20241022',
    'dependency': 'claude-3-5-sonnet-20241022',
    'debate': 'claude-3-5-sonnet-20241022',
    'remediation': 'claude-3-5-sonnet-20241022'
  })

  const [selectedModelProvider, setSelectedModelProvider] = useState<string>(Array.from(configuredProviders)[0] || 'groq')
  const [loading, setLoading] = useState(true)
  const [modelSearch, setModelSearch] = useState('')

  // Load agent configs from backend on mount
  useEffect(() => {
    fetch('/api/config/agent-models')
      .then(res => res.json())
      .then(data => {
        if (data.agents && Object.keys(data.agents).length > 0) {
          setAgentConfigs(data.agents)
        }
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to load agent configs:', err)
        setLoading(false)
      })
  }, [])

  // Get available models based on configured providers
  const getModelsForProvider = (providerId: string): string[] => {
    const providerModels: Record<string, string[]> = {
      'openai': ['gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-4o', 'gpt-4o-mini', 'gpt-4o-mini-2024-07-18', 'gpt-4-turbo', 'gpt-4-turbo-2024-04-09', 'gpt-4', 'gpt-4-0613', 'gpt-4-32k', 'gpt-4-32k-0613', 'gpt-3.5-turbo', 'gpt-3.5-turbo-16k', 'gpt-3.5-turbo-0613', 'o1', 'o1-mini', 'o1-preview', 'o3-mini', 'o3'],
      'anthropic': [
        'claude-fable-5', 'claude-mythos-5', 'claude-opus-4.8', 'claude-sonnet-4.6', 'claude-haiku-4.5',
        'claude-3.5-opus', 'claude-3.5-sonnet-20241022', 'claude-3.5-sonnet-20240620', 'claude-3.5-haiku-20241022',
        'claude-3-opus-20240229', 'claude-3-sonnet-20240229', 'claude-3-haiku-20240307',
        'claude-2.1', 'claude-2.0', 'claude-instant-1.2'
      ],
      'groq': ['llama-3.3-70b-versatile', 'llama-3.1-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768', 'gemma2-9b-it', 'whisper-large-v3', 'whisper-large-v3-turbo', 'groq/compound', 'groq/compound-mini', 'meta-llama/llama-4-scout-17b-16e-instruct', 'qwen/qwen3-32b', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'openai/gpt-oss-safeguard-20b', 'meta-llama/llama-prompt-guard-2-86m'],
      'openrouter': [
        // Special OpenRouter models
        'openrouter/auto', 'openrouter/free',
        // Meta LLama models (most reliable on OpenRouter)
        'meta-llama/llama-3.3-70b-instruct', 'meta-llama/llama-3.1-8b-instant', 'meta-llama/llama-3.1-70b-instruct',
        // Google models
        'google/gemini-2.0-flash-exp', 'google/gemini-2.0-flash',
        // Anthropic models (via OpenRouter)
        'anthropic/claude-3.5-sonnet', 'anthropic/claude-3.5-sonnet-20240620',
        // Mistral models
        'mistralai/mistral-small', 'mistralai/mistral-medium',
        // DeepSeek models
        'deepseek/deepseek-chat', 'deepseek/deepseek-coder',
        // Qwen models
        'qwen/qwen2.5-72b-instruct', 'qwen/qwen2.5-coder-32b',
        // Other popular models
        'cohere/command-r-plus', 'cohere/command-r',
        'x-ai/grok-2', 'x-ai/grok-2-mini',
        'perplexity/sonar', 'perplexity/sonar-pro',
        'microsoft/phi-4', 'snowflake/snowflake-arctic-instruct',
        'databricks/dbrx-instruct',
      ],
      'ollama': ['llama3.3', 'llama3.2', 'llama3.2-vision', 'llama3.1', 'llama3', 'llama2', 'codellama', 'codellama2', 'mistral', 'mistral-nemo', 'mixtral', 'phi3', 'phi3.5', 'phi4', 'gemma2', 'gemma2:27b', 'gemma', 'qwen2.5', 'qwen2.5-coder', 'qwen2.5-math', 'yi', 'yi-coder', 'yi2', 'deepseek-coder', 'deepseek-llm', 'command-r', 'command-r7b', 'llava', 'llava-llama3', 'bakllava', 'nomic-embed-text', 'all-minimum', 'shawj/neural-chat', 'zephyr', 'embd-01', 'eagle', 'fastchat', 'orca2', 'vicuna'],
      'lmstudio': ['auto', 'llama3.3', 'llama3.2', 'llama3.2-vision', 'llama3.1', 'llama3', 'llama2', 'codellama', 'codellama2', 'mistral', 'mistral-nemo', 'mixtral', 'phi3', 'phi4', 'gemma2', 'qwen2.5', 'qwen2.5-coder', 'yi', 'yi2', 'deepseek-coder', 'deepseek-llm', 'command-r', 'stablelm', 'smollm', 'gemma2:27b', 'qwen2.5-math'],
      'vllm': ['auto', 'llama3.3', 'llama3.2', 'llama3.2-vision', 'llama3.1', 'llama3', 'llama2', 'codellama', 'mistral', 'mistral-nemo', 'mixtral', 'phi3', 'phi4', 'qwen2.5', 'qwen2.5-coder', 'yi', 'yi2', 'deepseek-llm', 'gemma2', 'command-r'],
      'gemini': [
        'gemini-3.5-pro', 'gemini-3.5-flash', 'gemini-spark', 'gemini-omni',
        'gemini-3.1-pro', 'gemini-3.1-flash-lite', 'gemini-3-flash', 'gemini-3-ultra',
        'gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.5-flash-lite',
        'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-nano'
      ],
      'mistral': ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest', 'mistral-nemo', 'mistral-hoder', 'codestral', 'codestral-latest', 'mistral-embed', 'open-mistral-7b', 'open-mixtral-8x7b', 'open-mixtral-8x22b'],
      'opencode': [
        'big-pickle', 'stealth',
        'claude-fable-5', 'claude-haiku-4.5', 'claude-opus-4.1', 'claude-opus-4.5', 'claude-opus-4.6', 'claude-opus-4.7', 'claude-opus-4.8', 'claude-sonnet-4', 'claude-sonnet-4.5', 'claude-sonnet-4.6',
        'gpt-5', 'gpt-5-codex', 'gpt-5-nano', 'gpt-5.1', 'gpt-5.1-codex', 'gpt-5.1-codex-max', 'gpt-5.1-codex-mini', 'gpt-5.2', 'gpt-5.2-codex', 'gpt-5.3-codex', 'gpt-5.3-codex-spark', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.4-nano', 'gpt-5.4-pro', 'gpt-5.5', 'gpt-5.5-pro',
        'gemini-3-flash', 'gemini-3.1-pro', 'gemini-3.5-flash',
        'deepseek-v4-flash', 'deepseek-v4-flash-free', 'deepseek-v4-pro',
        'glm-5', 'glm-5.1',
        'kimi-k2.5', 'kimi-k2.6',
        'qwen3.5-plus', 'qwen3.6-plus', 'qwen3.6-plus-free', 'qwen3.7-plus', 'qwen3.7-max',
        'grok-build-0.1',
        'minimax-m2.5', 'minimax-m2.7', 'minimax-m3-free', 'minimax-m3',
        'mimo-v2.5-pro', 'mimo-v2.5-free',
        'nemotron-3-ultra-free',
        'north-mini-code-free'
      ],
    }
    return providerModels[providerId] || []
  }

  const agents = [
    { id: 'recon', name: '🎯 Recon Agent', description: 'Target discovery, port scanning, OSINT' },
    { id: 'code-review', name: '🔍 Code Review Agent', description: 'SAST with security pattern detection' },
    { id: 'threat-modeling', name: '🛡️ Threat Modeling Agent', description: 'Attack path analysis using knowledge graph' },
    { id: 'dependency', name: '📦 Dependency Agent', description: 'Vulnerability scanning for dependencies' },
    { id: 'debate', name: '⚖️ Debate Engine', description: '5-role adversarial finding validation' },
    { id: 'remediation', name: '🔧 Remediation Agent', description: 'Automated remediation planning' },
  ]

  // Get available models for selected provider, filtered by search
  const availableModels = getModelsForProvider(selectedModelProvider)
  const filteredModels = modelSearch.trim() 
    ? availableModels.filter(m => m.toLowerCase().includes(modelSearch.toLowerCase()))
    : availableModels
  
  // Update a specific agent's model
  const updateAgentModel = (agentId: string, model: string) => {
    setAgentConfigs(prev => ({ ...prev, [agentId]: model }))
  }

  const handleSave = async () => {
    try {
      const res = await fetch('/api/config/agent-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agents: agentConfigs }),
      })
      const data = await res.json()
      if (data.status === 'ok') {
        alert('Agent configuration saved!')
      } else {
        alert('Failed to save: ' + (data.error || 'Unknown error'))
      }
    } catch (e) {
      alert('Failed to save agent configuration')
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px' }}>🤖 Agent Model Configuration</h2>
      <p style={{ color: '#666', marginBottom: '32px' }}>Configure a specific model for each security agent</p>

      {/* Provider Selection for Model Dropdown */}
      <div style={{ background: '#12121a', borderRadius: '16px', padding: '24px', border: '1px solid #1a1a2e', marginBottom: '24px' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Model Provider</h3>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <select
            value={selectedModelProvider}
            onChange={(e) => setSelectedModelProvider(e.target.value)}
            disabled={configuredProviders.size === 0}
            style={{
              background: '#1a1a2e',
              border: '1px solid #2a2a3e',
              borderRadius: '8px',
              padding: '12px 16px',
              color: configuredProviders.size === 0 ? '#666' : '#fff',
              fontSize: '14px',
              minWidth: '200px'
            }}
          >
            {configuredProviders.size > 0 ? (
              Array.from(configuredProviders).map(providerId => (
                <option key={providerId} value={providerId}>{providerId.charAt(0).toUpperCase() + providerId.slice(1)}</option>
              ))
            ) : (
              <option value="">No providers configured</option>
            )}
          </select>
          <input
            type="text"
            value={modelSearch}
            onChange={(e) => setModelSearch(e.target.value)}
            placeholder="Search models..."
            style={{
              background: '#1a1a2e',
              border: '1px solid #2a2a3e',
              borderRadius: '8px',
              padding: '12px 16px',
              color: '#fff',
              fontSize: '14px',
              minWidth: '250px',
              flex: 1
            }}
          />
          <span style={{ fontSize: '12px', color: '#666' }}>
            {configuredProviders.size > 0 
              ? `Showing ${filteredModels.length} of ${availableModels.length} models from ${selectedModelProvider}`
              : 'Configure a provider in Settings first'}
          </span>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>Loading agent configurations...</div>
      ) : (
      /* Per-Agent Model Configuration */
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: '16px' }}>
        {agents.map(agent => (
          <div key={agent.id} style={{
            background: '#12121a',
            borderRadius: '16px',
            padding: '20px',
            border: '1px solid #1a1a2e'
          }}>
            {/* Agent Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ 
                fontSize: '24px',
                width: '40px',
                height: '40px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: '#1a1a2e',
                borderRadius: '10px'
              }}>
                {agent.name.split(' ')[0]}
              </div>
              <div>
                <div style={{ fontSize: '14px', fontWeight: '600' }}>{agent.name}</div>
                <div style={{ fontSize: '11px', color: '#666' }}>{agent.description}</div>
              </div>
            </div>
            
            {/* Model Selection for this Agent */}
            <div>
              <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '12px' }}>Model</label>
              {filteredModels.length > 0 ? (
                <select
                  value={agentConfigs[agent.id] || filteredModels[0]}
                  onChange={(e) => updateAgentModel(agent.id, e.target.value)}
                  style={{
                    width: '100%',
                    background: '#1a1a2e',
                    border: '1px solid #2a2a3e',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#00d4ff',
                    fontSize: '13px',
                    fontFamily: 'monospace'
                  }}
                >
                  {filteredModels.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  value={agentConfigs[agent.id] || ''}
                  onChange={(e) => updateAgentModel(agent.id, e.target.value)}
                  placeholder="Enter model name..."
                  style={{
                    width: '100%',
                    background: '#1a1a2e',
                    border: '1px solid #2a2a3e',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#00d4ff',
                    fontSize: '13px',
                    fontFamily: 'monospace'
                  }}
                />
              )}
            </div>
          </div>
        ))}
      </div>
      )}
      
      <button onClick={handleSave} style={{
        marginTop: '24px',
        background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
        color: '#000',
        border: 'none',
        borderRadius: '8px',
        padding: '14px 28px',
        fontWeight: '700',
        cursor: 'pointer',
        fontSize: '14px'
      }}>
        Save Agent Configuration
      </button>

      {/* Provider Status */}
      <div style={{ marginTop: '24px', background: '#12121a', borderRadius: '16px', padding: '24px', border: '1px solid #1a1a2e' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '20px' }}>Model Provider Selection</h3>
        
        {/* Provider Selector for Models */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Select Provider for Model Dropdown</label>
          <select
            value={selectedModelProvider}
            onChange={(e) => setSelectedModelProvider(e.target.value)}
            disabled={configuredProviders.size === 0}
            style={{
              width: '100%',
              background: '#1a1a2e',
              border: '1px solid #2a2a3e',
              borderRadius: '8px',
              padding: '12px',
              color: configuredProviders.size === 0 ? '#666' : '#fff',
              fontSize: '14px'
            }}
          >
            {configuredProviders.size > 0 ? (
              Array.from(configuredProviders).map(providerId => (
                <option key={providerId} value={providerId}>{providerId.charAt(0).toUpperCase() + providerId.slice(1)}</option>
              ))
            ) : (
              <option value="">No providers configured</option>
            )}
          </select>
          <p style={{ fontSize: '11px', color: '#666', marginTop: '4px' }}>
            {configuredProviders.size > 0 
              ? `Showing models for ${selectedModelProvider}. Only configured providers are available.`
              : 'Go to Settings to configure a provider first.'}
          </p>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
          {configuredProviders.size > 0 ? (
            Array.from(configuredProviders).map(providerId => (
              <div key={providerId} style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                background: selectedModelProvider === providerId ? 'rgba(0, 212, 255, 0.1)' : '#1a1a2e',
                borderRadius: '8px',
                border: selectedModelProvider === providerId ? '1px solid #00d4ff' : '1px solid #00ff8840',
                cursor: 'pointer'
              }}
              onClick={() => setSelectedModelProvider(providerId)}
              >
                <span style={{ fontSize: '16px' }}>✅</span>
                <span style={{ fontWeight: '600', textTransform: 'capitalize' }}>{providerId}</span>
                <span style={{ fontSize: '11px', color: '#888' }}>
                  {getModelsForProvider(providerId).length} models
                </span>
              </div>
            ))
          ) : (
            <p style={{ color: '#666', padding: '20px' }}>No providers configured. Go to Settings to configure a provider.</p>
          )}
        </div>
      </div>
    </div>
  )
}

function LoadingSpinner() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '80px' }}>
      <div style={{
        width: '48px',
        height: '48px',
        border: '3px solid #1a1a2e',
        borderTopColor: '#00d4ff',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite'
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}

// ============ AGENTS PANEL (Phase 3) ============
function AgentsPanel({ runningAgent, onRunAgent, output }: { 
  runningAgent: string | null;
  onRunAgent: (agent: string, action: string, data: any) => void;
  output: string;
}) {
  const agents = [
    { id: 'recon', name: '🎯 Recon Agent', description: 'Target discovery, port scanning, OSINT', color: '#00d4ff' },
    { id: 'code-review', name: '🔍 Code Review Agent', description: 'SAST with security pattern detection', color: '#00ff88' },
    { id: 'threat-modeling', name: '🛡️ Threat Modeling Agent', description: 'Attack path analysis using knowledge graph', color: '#ff8844' },
    { id: 'dependency', name: '📦 Dependency Agent', description: 'Vulnerability scanning for dependencies', color: '#aa88ff' },
    { id: 'debate', name: '⚖️ Debate Engine', description: '5-role adversarial finding validation', color: '#ffaa00' },
  ]
  
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Agent Cards */}
      <div>
        <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>Phase 3 Agents</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {agents.map(agent => (
            <div key={agent.id} style={{
              background: '#12121a',
              border: `1px solid ${agent.color}40`,
              borderRadius: '12px',
              padding: '16px',
              cursor: runningAgent ? 'not-allowed' : 'pointer',
              opacity: runningAgent ? 0.6 : 1,
              transition: 'all 0.2s',
            }}
            onClick={() => !runningAgent && onRunAgent(agent.id, 'discover', { scope: { domains: ['example.com'] } })}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: '16px', fontWeight: '600', color: agent.color }}>{agent.name}</div>
                {runningAgent === agent.id && <span style={{ fontSize: '12px', color: '#888' }}>Running...</span>}
              </div>
              <p style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>{agent.description}</p>
            </div>
          ))}
        </div>
        
        <div style={{ marginTop: '16px', padding: '12px', background: '#1a1a2e', borderRadius: '8px', fontSize: '12px', color: '#888' }}>
          💡 Click an agent to run it with default parameters. Agents will analyze the project and create findings.
        </div>
      </div>
      
      {/* Agent Output */}
      <div>
        <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>Agent Output</h3>
        <div style={{
          background: '#0a0a0f',
          border: '1px solid #1a1a2e',
          borderRadius: '12px',
          padding: '16px',
          minHeight: '400px',
          maxHeight: '500px',
          overflow: 'auto',
          fontFamily: 'monospace',
          fontSize: '12px',
          whiteSpace: 'pre-wrap',
          color: output.includes('error') || output.includes('Error') ? '#ff4444' : '#00ff88',
        }}>
          {output || 'Run an agent to see output here...'}
        </div>
      </div>
    </div>
  )
}

// ============ ANALYSIS PANEL ============
function AnalysisPanel({ projectId }: { projectId: string }) {
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [codeInput, setCodeInput] = useState('// Paste vulnerable code here\nconst query = "SELECT * FROM users WHERE id = " + userId;')
  
  const runCodeAnalysis = async () => {
    try {
      const res = await fetch(`/api/projects/${projectId}/analyze/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: codeInput, file_path: 'example.js', language: 'javascript' }),
      })
      const data = await res.json()
      setAnalysisResult(data)
    } catch (e) {
      console.error('Analysis failed:', e)
    }
  }
  
  return (
    <div>
      <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>Code Analysis (SAST)</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div>
          <textarea
            value={codeInput}
            onChange={(e) => setCodeInput(e.target.value)}
            style={{
              width: '100%',
              minHeight: '300px',
              background: '#0a0a0f',
              border: '1px solid #1a1a2e',
              borderRadius: '8px',
              padding: '12px',
              color: '#00d4ff',
              fontFamily: 'monospace',
              fontSize: '13px',
              resize: 'vertical',
            }}
            placeholder="Paste code to analyze..."
          />
          <button onClick={runCodeAnalysis} style={{
            marginTop: '12px',
            background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
            color: '#000',
            border: 'none',
            borderRadius: '8px',
            padding: '12px 24px',
            fontWeight: '700',
            cursor: 'pointer',
          }}>
            Analyze Code
          </button>
        </div>
        
        <div style={{ background: '#12121a', borderRadius: '12px', padding: '16px', border: '1px solid #1a1a2e' }}>
          <h4 style={{ fontSize: '14px', marginBottom: '12px' }}>Analysis Results</h4>
          {analysisResult ? (
            <div style={{ fontFamily: 'monospace', fontSize: '12px' }}>
              <div style={{ marginBottom: '8px', color: '#888' }}>Patterns Found: <span style={{ color: '#00d4ff' }}>{analysisResult.summary?.patterns_found || 0}</span></div>
              <div style={{ marginBottom: '8px', color: '#888' }}>Critical: <span style={{ color: '#ff4444' }}>{analysisResult.summary?.critical || 0}</span></div>
              <div style={{ marginBottom: '8px', color: '#888' }}>High: <span style={{ color: '#ff8844' }}>{analysisResult.summary?.high || 0}</span></div>
              <div style={{ marginBottom: '12px', color: '#888' }}>Unsafe Flows: <span style={{ color: '#ffaa00' }}>{analysisResult.summary?.unsafe_flows || 0}</span></div>
              
              {analysisResult.patterns?.length > 0 && (
                <div style={{ marginTop: '16px' }}>
                  <div style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>Vulnerabilities:</div>
                  {analysisResult.patterns.map((p: any, i: number) => (
                    <div key={i} style={{
                      background: '#1a1a2e',
                      padding: '8px',
                      borderRadius: '4px',
                      marginBottom: '4px',
                      borderLeft: `3px solid ${p.severity === 'critical' ? '#ff4444' : p.severity === 'high' ? '#ff8844' : '#ffaa00'}`
                    }}>
                      <div style={{ fontWeight: '600', color: '#fff' }}>{p.name}</div>
                      <div style={{ fontSize: '11px', color: '#666' }}>{p.description}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: '#666', fontSize: '13px' }}>Run analysis to see results</div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App