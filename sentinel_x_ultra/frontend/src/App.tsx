import { useState, useEffect } from 'react'

import { InputSourcesPanel, ThreatHuntPanel, SupplyChainPanel } from './panel_components'



// ============ TYPE DEFINITIONS ============

interface Project {

  project_id: string

  name: string

  created_at: string

  findings_count?: number

  critical_count?: number

  high_count?: number

}



interface HealthStatus {

  status: string

  version: string

  providers: string[]

  phase5_enabled?: boolean

}



interface AgentModelConfig {

  [agentId: string]: string

}



interface Finding {

  id: string

  type: string

  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'

  title: string

  description: string

  location?: string

  cwe?: string

  owasp?: string[]

}



interface ThreatAlert {

  id: string

  type: string

  severity: 'critical' | 'high' | 'medium' | 'low'

  title: string

  description: string

  timestamp: string

  iocs?: string[]

  yara_matches?: string[]

}



interface SBOMEntry {

  name: string

  version: string

  license: string

  vulnerabilities: string[]

  risk_score: number

}







// ============ MAIN APP ============

function App() {

  const [view, setView] = useState<'dashboard' | 'models' | 'settings'>('dashboard')

  const [projects, setProjects] = useState<Project[]>([])

  const [health, setHealth] = useState<HealthStatus | null>(null)

  const [loading, setLoading] = useState(true)
  const [isFullScanning, setIsFullScanning] = useState(false)

  const [currentProject, setCurrentProject] = useState<Project | null>(null)

  const [configuredProviders, setConfiguredProviders] = useState<Set<string>>(new Set())

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  const [notifications, setNotifications] = useState<{id: string, message: string, type: string}[]>([])



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



  const createProject = async (name: string, folder?: string, target?: string) => {
    try {
      const body: any = { name }
      if (folder) body.folder = folder
      if (target) body.target = target
      const res = await fetch('/api/projects', {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({ name }),

      })

      const data = await res.json()

      const newProject = { 

        project_id: data.project_id, 

        name: data.name, 

        created_at: new Date().toISOString(),

        findings_count: 0,

        critical_count: 0,

        high_count: 0

      }

      setProjects([...projects, newProject])

      addNotification('success', `Project "${name}" created successfully`)

    } catch (e) {

      console.error('Failed to create project:', e)

      addNotification('error', 'Failed to create project')

    }

  }



  const deleteProject = async (projectId: string) => {

    if (!confirm('Are you sure you want to delete this project?')) return

    try {

      await fetch(`/api/projects/${projectId}`, { method: 'DELETE' })

      setProjects(projects.filter(p => p.project_id !== projectId))

      if (currentProject?.project_id === projectId) {

        setCurrentProject(null)

        setView('dashboard')

      }

      addNotification('info', 'Project deleted')

    } catch (e) {

      console.error('Failed to delete project:', e)

    }

  }



  const addNotification = (type: string, message: string) => {

    const id = Date.now().toString()

    setNotifications(prev => [...prev, { id, message, type }])

    setTimeout(() => {

      setNotifications(prev => prev.filter(n => n.id !== id))

    }, 4000)

  }



  return (

    <div style={{ 

      minHeight: '100vh', 

      background: 'linear-gradient(135deg, #0a0a0f 0%, #0f0f1a 50%, #0a0a0f 100%)',

      color: '#fff',

      display: 'flex'

    }}>

      {/* Notifications Toast */}

      <div style={{

        position: 'fixed',

        top: '20px',

        right: '20px',

        zIndex: 1000,

        display: 'flex',

        flexDirection: 'column',

        gap: '8px'

      }}>

        {notifications.map(n => (

          <div key={n.id} style={{

            background: n.type === 'success' ? '#00ff88' : n.type === 'error' ? '#ff4444' : '#00d4ff',

            color: '#000',

            padding: '12px 20px',

            borderRadius: '8px',

            fontWeight: '600',

            fontSize: '13px',

            boxShadow: '0 4px 20px rgba(0,0,0,0.3)',

            animation: 'slideIn 0.3s ease'

          }}>

            {n.message}

          </div>

        ))}

      </div>



      {/* Sidebar */}

      <aside style={{

        width: sidebarCollapsed ? '70px' : '260px',

        minHeight: '100vh',

        background: 'rgba(15, 15, 26, 0.95)',

        borderRight: '1px solid rgba(255,255,255,0.05)',

        backdropFilter: 'blur(10px)',

        display: 'flex',

        flexDirection: 'column',

        transition: 'width 0.3s ease',

        position: 'fixed',

        left: 0,

        top: 0,

        zIndex: 100

      }}>

        {/* Logo */}

        <div style={{

          padding: '20px',

          borderBottom: '1px solid rgba(255,255,255,0.05)',

          display: 'flex',

          alignItems: 'center',

          gap: '12px',

          overflow: 'hidden'

        }}>

          <div style={{ 

            fontSize: '28px',

            flexShrink: 0

          }}>🛡️</div>

          {!sidebarCollapsed && (

            <div style={{ overflow: 'hidden' }}>

              <h1 style={{ 

                fontSize: '16px', 

                fontWeight: 'bold', 

                background: 'linear-gradient(90deg, #00d4ff, #00ff88)',

                WebkitBackgroundClip: 'text',

                WebkitTextFillColor: 'transparent',

                whiteSpace: 'nowrap'

              }}>

                SENTINEL-X ULTRA

              </h1>

              <span style={{ fontSize: '10px', color: '#666' }}>v0.5.0 • Phase 5</span>

            </div>

          )}

        </div>



        {/* Navigation */}        <nav style={{ flex: 1, padding: '16px 12px' }}>
          <NavItem 
            icon="📊" 
            label="Dashboard" 
            active={view === 'dashboard' && !currentProject} 
            collapsed={sidebarCollapsed}
            onClick={() => { setView('dashboard'); setCurrentProject(null) }}
          />
          <NavItem 
            icon="🤖" 
            label="Models" 
            active={view === 'models'} 
            collapsed={sidebarCollapsed}
            onClick={() => setView('models')}
          />
          <NavItem 
            icon="⚙️" 
            label="Settings" 
            active={view === 'settings'} 
            collapsed={sidebarCollapsed}
            onClick={() => setView('settings')}
          />
        </nav>



        {/* Collapse Toggle */}

        <button 

          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}

          style={{

            margin: '12px',

            padding: '10px',

            background: 'rgba(255,255,255,0.05)',

            border: 'none',

            borderRadius: '8px',

            color: '#666',

            cursor: 'pointer',

            fontSize: '14px',

            transition: 'all 0.2s'

          }}

        >

          {sidebarCollapsed ? '→' : '← Collapse'}

        </button>



        {/* Health Status */}

        {!sidebarCollapsed && (

          <div style={{

            padding: '16px',

            margin: '12px',

            background: 'rgba(0,255,136,0.1)',

            borderRadius: '8px',

            border: '1px solid rgba(0,255,136,0.2)'

          }}>

            <div style={{ fontSize: '12px', color: '#00ff88', marginBottom: '4px' }}>

              ● {health?.status === 'ok' ? 'System Online' : 'System Offline'}

            </div>

            <div style={{ fontSize: '11px', color: '#666' }}>

              {health?.providers?.length || 0} providers • {projects.length} projects

            </div>

          </div>

        )}

      </aside>



      {/* Main Content */}

      <main style={{

        flex: 1,

        marginLeft: sidebarCollapsed ? '70px' : '260px',

        transition: 'margin-left 0.3s ease',

        minHeight: '100vh'

      }}>

        {/* Header */}

        <header style={{

          padding: '20px 32px',

          borderBottom: '1px solid rgba(255,255,255,0.05)',

          display: 'flex',

          justifyContent: 'space-between',

          alignItems: 'center',

          background: 'rgba(10, 10, 15, 0.8)',

          backdropFilter: 'blur(10px)',

          position: 'sticky',

          top: 0,

          zIndex: 50

        }}>          <div>
            <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '4px' }}>
              {currentProject ? currentProject.name : 'Security Dashboard'}
            </h2>
            <p style={{ fontSize: '13px', color: '#666' }}>
              {currentProject ? `Project ID: ${currentProject.project_id}` : 'Manage projects and run security analysis'}
            </p>
          </div>

          

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>

            <button style={{

              background: 'rgba(255,255,255,0.05)',

              border: '1px solid rgba(255,255,255,0.1)',

              color: '#888',

              padding: '10px 16px',

              borderRadius: '8px',

              cursor: 'pointer',

              fontSize: '13px'

            }}>

              🔔 0

            </button>

            <button style={{

              background: 'linear-gradient(135deg, #00d4ff, #00ff88)',

              border: 'none',

              color: '#000',

              padding: '10px 20px',

              borderRadius: '8px',

              fontWeight: '700',

              cursor: 'pointer',

              fontSize: '13px'

            }} onClick={async () => {
              if (!currentProject) { addNotification('error', 'Open a project first'); return }
              setIsFullScanning(true)
              try {
                const res = await fetch('/api/projects/' + currentProject.project_id + '/full-scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
                if (!res.ok) throw new Error('HTTP ' + res.status)
                const data = await res.json()
                addNotification(data.findings_total === 0 ? 'info' : 'success', data.findings_total === 0 ? 'Full scan complete: no findings across ' + (data.agents_run ?? 0) + ' agents' : ('Full scan complete: ' + data.findings_total + ' findings across ' + (data.agents_run ?? 0) + ' agents'))
              } catch (e: any) {
                addNotification('error', 'Scan failed: ' + (e?.message || 'unknown'))
              } finally {
                setIsFullScanning(false)
              }
            }} disabled={isFullScanning}>
              {isFullScanning ? '\u25cf Scanning...' : '+ Full Scan'}
            </button>

          </div>

        </header>



        {/* Page Content */}

        <div style={{ padding: '32px' }}>

          {loading ? (

            <LoadingSpinner />

          ) : currentProject ? (

            <ProjectView project={currentProject} onBack={() => { setCurrentProject(null); setView('dashboard') }} addNotification={addNotification} />

          ) : view === 'settings' ? (

            <SetupView configuredProviders={configuredProviders} onProviderConfigured={(providerId) => {

              setConfiguredProviders(prev => new Set([...prev, providerId]))

              addNotification('success', `${providerId} configured successfully`)

            }} />

          ) : view === 'models' ? (

            <AgentModelsView   />          ) : (

            <DashboardView 

              projects={projects} 

              onCreateProject={createProject} 

              onDeleteProject={deleteProject} 

              onOpenProject={(p) => setCurrentProject(p)}

              health={health}

            />

          )}

        </div>

      </main>



      <style>{`

        @keyframes slideIn {

          from { transform: translateX(100%); opacity: 0; }

          to { transform: translateX(0); opacity: 1; }

        }

        @keyframes pulse {

          0%, 100% { opacity: 1; }

          50% { opacity: 0.5; }

        }

        @keyframes glow {

          0%, 100% { box-shadow: 0 0 20px rgba(0, 212, 255, 0.3); }

          50% { box-shadow: 0 0 40px rgba(0, 212, 255, 0.6); }

        }

      `}</style>

    </div>

  )

}// getViewDescription removed - features now integrated into project tabs



// ============ NAVIGATION ITEM ============

function NavItem({ icon, label, active, collapsed, onClick, badge }: { 

  icon: string; 

  label: string; 

  active: boolean; 

  collapsed: boolean;

  onClick: () => void;

  badge?: string;

}) {

  return (

    <button 

      onClick={onClick}

      style={{

        width: '100%',

        display: 'flex',

        alignItems: 'center',

        gap: '12px',

        padding: collapsed ? '12px' : '12px 16px',

        marginBottom: '4px',

        background: active ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.15), rgba(0, 255, 136, 0.1))' : 'transparent',

        border: active ? '1px solid rgba(0, 212, 255, 0.3)' : '1px solid transparent',

        borderRadius: '10px',

        color: active ? '#00d4ff' : '#888',

        cursor: 'pointer',

        transition: 'all 0.2s',

        justifyContent: collapsed ? 'center' : 'flex-start',

        position: 'relative',

        overflow: 'hidden'

      }}

    >

      <span style={{ fontSize: '18px', flexShrink: 0 }}>{icon}</span>

      {!collapsed && (

        <>

          <span style={{ fontSize: '14px', fontWeight: active ? '600' : '400', flex: 1 }}>{label}</span>

          {badge && (

            <span style={{

              background: 'linear-gradient(135deg, #ff8844, #ff4488)',

              color: '#fff',

              fontSize: '9px',

              fontWeight: '700',

              padding: '2px 6px',

              borderRadius: '4px'

            }}>

              {badge}

            </span>

          )}

        </>

      )}

      {active && (

        <div style={{

          position: 'absolute',

          left: 0,

          top: '50%',

          transform: 'translateY(-50%)',

          width: '3px',

          height: '60%',

          background: 'linear-gradient(180deg, #00d4ff, #00ff88)',

          borderRadius: '0 2px 2px 0'

        }} />

      )}

    </button>

  )

}



// ============ DASHBOARD VIEW ============

function DashboardView({ projects, onCreateProject, onDeleteProject, onOpenProject, health }: {

  projects: Project[];

  onCreateProject: (name: string) => void;

  onDeleteProject: (id: string) => void;

  onOpenProject: (project: Project) => void;

  health: HealthStatus | null;

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



  const stats = {

    totalFindings: projects.reduce((sum, p) => sum + (p.findings_count || 0), 0),

    criticalIssues: projects.reduce((sum, p) => sum + (p.critical_count || 0), 0),

    activeProjects: projects.length,

    providersActive: health?.providers?.length || 0

  }



  return (

    <div>

      {/* Stats Cards */}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '32px' }}>

        <StatCard 

          label="Total Findings" 

          value={stats.totalFindings.toString()} 

          icon="🎯"

          color="#00d4ff"

        />

        <StatCard 

          label="Critical Issues" 

          value={stats.criticalIssues.toString()} 

          icon="🚨"

          color="#ff4444"

        />

        <StatCard 

          label="Active Projects" 

          value={stats.activeProjects.toString()} 

          icon="📁"

          color="#00ff88"

        />

        <StatCard 

          label="Providers" 

          value={stats.providersActive.toString()} 

          icon="⚡"

          color="#ffaa00"

        />

      </div>
      {/* Create Project */}

      <div style={{ 

        background: 'rgba(15, 15, 26, 0.95)',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255,255,255,0.05)',

        marginBottom: '32px'

      }}>

        <form onSubmit={handleCreate} style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>

          <input

            type="text"

            value={newProjectName}

            onChange={(e) => setNewProjectName(e.target.value)}

            placeholder="Enter project name to start security analysis..."

            style={{

              flex: 1,

              background: 'rgba(0,0,0,0.3)',

              border: '1px solid rgba(255,255,255,0.1)',

              borderRadius: '10px',

              padding: '14px 18px',

              color: '#fff',

              fontSize: '14px',

              outline: 'none',

              transition: 'border-color 0.2s'

            }}

            onFocus={(e) => e.target.style.borderColor = '#00d4ff'}

            onBlur={(e) => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}

          />

          <button

            type="submit"

            style={{

              background: 'linear-gradient(135deg, #00d4ff, #00ff88)',

              color: '#000',

              border: 'none',

              borderRadius: '10px',

              padding: '14px 28px',

              fontWeight: '700',

              cursor: 'pointer',

              fontSize: '14px',

              display: 'flex',

              alignItems: 'center',

              gap: '8px'

            }}

          >

            <span>+</span> New Project

          </button>

        </form>

      </div>



      {/* Projects Grid */}

      <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '16px', color: '#888' }}>Your Projects</h3>

      {projects.length === 0 ? (

        <EmptyState 

          icon="🎯"

          title="No projects yet"

          description="Create your first project to start security analysis with AI-powered agents"

        />

      ) : (

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '20px' }}>

          {projects.map((project) => (

            <ProjectCard 

              key={project.project_id} 

              project={project} 

              onOpen={() => onOpenProject(project)}

              onDelete={() => setShowDeleteConfirm(project.project_id)}

              showDeleteConfirm={showDeleteConfirm === project.project_id}

              onConfirmDelete={() => { onDeleteProject(project.project_id); setShowDeleteConfirm(null) }}

              onCancelDelete={() => setShowDeleteConfirm(null)}

            />

          ))}

        </div>

      )}

    </div>

  )

}



function StatCard({ label, value, icon, color, trend }: { 

  label: string; 

  value: string; 

  icon: string;

  color: string;

  trend?: string;

}) {

  return (

    <div style={{

      background: 'rgba(15, 15, 26, 0.95)',

      borderRadius: '16px',

      padding: '24px',

      border: `1px solid ${color}30`,

      position: 'relative',

      overflow: 'hidden'

    }}>

      <div style={{

        position: 'absolute',

        top: '-20px',

        right: '-20px',

        width: '80px',

        height: '80px',

        background: `${color}15`,

        borderRadius: '50%'

      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>

        <div style={{ fontSize: '32px' }}>{icon}</div>

        {trend && (

          <span style={{

            background: trend.startsWith('+') ? '#00ff8830' : '#ff444430',

            color: trend.startsWith('+') ? '#00ff88' : '#ff4444',

            fontSize: '11px',

            fontWeight: '600',

            padding: '4px 8px',

            borderRadius: '4px'

          }}>

            {trend}

          </span>

        )}

      </div>

      <div style={{ fontSize: '36px', fontWeight: 'bold', color, marginBottom: '4px' }}>{value}</div>

      <div style={{ fontSize: '13px', color: '#666' }}>{label}</div>

    </div>

  )

}



function ProjectCard({ project, onOpen, onDelete, showDeleteConfirm, onConfirmDelete, onCancelDelete }: {

  project: Project;

  onOpen: () => void;

  onDelete: () => void;

  showDeleteConfirm: boolean;

  onConfirmDelete: () => void;

  onCancelDelete: () => void;

}) {

  return (

    <div style={{

      background: 'rgba(15, 15, 26, 0.95)',

      borderRadius: '16px',

      padding: '20px',

      border: '1px solid rgba(255,255,255,0.05)',

      transition: 'all 0.2s',

      cursor: 'pointer',

      position: 'relative'

    }}

    onClick={onOpen}

    onMouseEnter={(e) => {

      e.currentTarget.style.borderColor = 'rgba(0, 212, 255, 0.3)'

      e.currentTarget.style.transform = 'translateY(-2px)'

    }}

    onMouseLeave={(e) => {

      e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'

      e.currentTarget.style.transform = 'translateY(0)'

    }}>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>

        <h3 style={{ fontSize: '18px', fontWeight: '600' }}>{project.name}</h3>

        <button 

          onClick={(e) => { e.stopPropagation(); onDelete() }}

          style={{

            background: 'rgba(255,68,68,0.1)',

            border: 'none',

            color: '#ff4444',

            padding: '6px 12px',

            borderRadius: '6px',

            cursor: 'pointer',

            fontSize: '12px'

          }}

        >

          Delete

        </button>

      </div>

      

      <p style={{ fontSize: '12px', color: '#666', marginBottom: '16px' }}>

        Created {new Date(project.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}

      </p>

      

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>

        <span style={{ 

          fontSize: '11px', 

          background: 'rgba(0, 212, 255, 0.1)', 

          color: '#00d4ff', 

          padding: '4px 10px', 

          borderRadius: '4px',

          border: '1px solid rgba(0, 212, 255, 0.2)'

        }}>

          {project.findings_count || 0} findings

        </span>

        <span style={{ 

          fontSize: '11px', 

          background: 'rgba(255, 68, 68, 0.1)', 

          color: '#ff4444', 

          padding: '4px 10px', 

          borderRadius: '4px',

          border: '1px solid rgba(255, 68, 68, 0.2)'

        }}>

          {project.critical_count || 0} critical

        </span>

        <span style={{ 

          fontSize: '11px', 

          background: 'rgba(0, 255, 136, 0.1)', 

          color: '#00ff88', 

          padding: '4px 10px', 

          borderRadius: '4px',

          border: '1px solid rgba(0, 255, 136, 0.2)'

        }}>

          ● Ready

        </span>

      </div>



      {/* Phase badges */}

      <div style={{ display: 'flex', gap: '6px', marginTop: '12px' }}>

        {['P2', 'P3', 'P4', 'P5'].map(phase => (

          <span key={phase} style={{

            fontSize: '9px',

            background: phase === 'P5' ? 'linear-gradient(135deg, #ff8844, #ff4488)' : 'rgba(255,255,255,0.05)',

            color: phase === 'P5' ? '#fff' : '#666',

            padding: '3px 8px',

            borderRadius: '4px',

            fontWeight: '600'

          }}>

            {phase}

          </span>

        ))}

      </div>



      {/* Delete Confirmation Overlay */}

      {showDeleteConfirm && (

        <div style={{

          position: 'absolute',

          inset: 0,

          background: 'rgba(0,0,0,0.95)',

          borderRadius: '16px',

          display: 'flex',

          flexDirection: 'column',

          alignItems: 'center',

          justifyContent: 'center',

          gap: '12px'

        }}>

          <p style={{ fontSize: '14px', fontWeight: '600' }}>Delete "{project.name}"?</p>

          <div style={{ display: 'flex', gap: '8px' }}>

            <button onClick={(e) => { e.stopPropagation(); onConfirmDelete() }} style={{

              background: '#ff4444',

              color: '#fff',

              border: 'none',

              padding: '8px 16px',

              borderRadius: '6px',

              cursor: 'pointer',

              fontSize: '12px'

            }}>

              Confirm

            </button>

            <button onClick={(e) => { e.stopPropagation(); onCancelDelete() }} style={{

              background: 'rgba(255,255,255,0.1)',

              color: '#888',

              border: 'none',

              padding: '8px 16px',

              borderRadius: '6px',

              cursor: 'pointer',

              fontSize: '12px'

            }}>

              Cancel

            </button>

          </div>

        </div>

      )}

    </div>

  )

}



function EmptyState({ icon, title, description }: { icon: string; title: string; description: string }) {

  return (

    <div style={{

      textAlign: 'center',

      padding: '80px 40px',

      background: 'rgba(15, 15, 26, 0.95)',

      borderRadius: '16px',

      border: '1px dashed rgba(255,255,255,0.1)'

    }}>

      <div style={{ fontSize: '64px', marginBottom: '16px' }}>{icon}</div>

      <h3 style={{ fontSize: '20px', marginBottom: '8px' }}>{title}</h3>

      <p style={{ color: '#666', marginBottom: '24px' }}>{description}</p>

    </div>

  )

}



// ============ PROJECT VIEW ============

function ProjectView({ project, onBack, addNotification }: { 

  project: Project; 

  onBack: () => void;

  addNotification: (type: string, message: string) => void;

}) {

  const [activeTab, setActiveTab] = useState<'overview' | 'input' | 'analysis' | 'agents' | 'findings' | 'ai-report'>('overview')
  const [analysisFocus, setAnalysisFocus] = useState<'general' | 'threat-hunt' | 'supply-chain'>('general')

  const [agentOutput, setAgentOutput] = useState<string>('')

  const [runningAgent, setRunningAgent] = useState<string | null>(null)

  const [selectedPhase5Agent, setSelectedPhase5Agent] = useState<string>('threat_intelligence')



  const runAgent = async (agentType: string, action: string, inputData: any) => {

    setRunningAgent(agentType)

    setAgentOutput('Initializing agent...')

    try {

      const res = await fetch(`/api/projects/${project.project_id}/agents/${agentType}`, {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({ action, input_data: inputData }),

      })

      const data = await res.json()

      setAgentOutput(JSON.stringify(data, null, 2))

      addNotification('success', `${agentType} completed successfully`)

    } catch (e) {

      setAgentOutput(`Error: ${e}`)

      addNotification('error', `Agent ${agentType} failed`)

    } finally {

      setRunningAgent(null)    }
  }

  const tabs = [
    { id: 'overview',  label: 'Overview',       icon: '📊', bio: 'Project dashboard, recent activity, and quick actions to start a new assessment.' },
    { id: 'input',     label: 'Input Sources',  icon: '📥', bio: 'Feed the system with code, URLs, folders, Burp Suite history, or natural-language prompts.' },
    { id: 'analysis',  label: 'Analysis',       icon: '🔍', bio: 'Run code review, web testing, threat hunt, and supply-chain analysis from a single workspace. Pick a focus from the dropdown to switch modes.' },
    { id: 'agents',    label: 'Agents',         icon: '🤖', bio: 'Orchestrate the multi-agent framework: recon, code review, threat modeling, debate, remediation, and Phase 5 advanced agents.' },
    { id: 'findings',  label: 'Findings',       icon: '🎯', bio: 'Browse validated findings, view evidence, attack chains, and export reports in the Blank.md shape.' },
    { id: 'ai-report', label: 'AI Report',       icon: '📝', bio: 'Have the configured model write a Blank.md report from the findings it thinks are worth reporting to the company.' },
  ]



  return (

    <div>

      {/* Back Button and Title */}

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>

        <button onClick={onBack} style={{

          background: 'rgba(255,255,255,0.05)',

          border: '1px solid rgba(255,255,255,0.1)',

          color: '#888',

          padding: '10px 16px',

          borderRadius: '8px',

          cursor: 'pointer',

          fontSize: '13px',

          transition: 'all 0.2s'

        }}

        onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00d4ff'; e.currentTarget.style.color = '#00d4ff' }}

        onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'; e.currentTarget.style.color = '#888' }}>

          ← Back

        </button>

        <div>

          <h1 style={{ fontSize: '28px', fontWeight: 'bold', marginBottom: '4px' }}>{project.name}</h1>

          <p style={{ fontSize: '12px', color: '#666' }}>Project ID: {project.project_id}</p>

        </div>

      </div>



      {/* Tab Navigation */}

      <div style={{ 

        display: 'flex', 

        gap: '8px', 

        marginBottom: '24px', 

        borderBottom: '1px solid rgba(255,255,255,0.05)', 

        paddingBottom: '16px',

        overflowX: 'auto'

      }}>

        {tabs.map(tab => (

          <button key={tab.id} onClick={() => setActiveTab(tab.id as any)}

            style={{

              background: activeTab === tab.id 

                ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(0, 255, 136, 0.1))' 

                : 'transparent',

              color: activeTab === tab.id ? '#00d4ff' : '#888',

              border: activeTab === tab.id ? '1px solid rgba(0, 212, 255, 0.3)' : '1px solid transparent',

              padding: '12px 20px',

              borderRadius: '10px',

              cursor: 'pointer',

              fontWeight: '600',

              fontSize: '14px',

              display: 'flex',

              alignItems: 'center',

              gap: '8px',

              whiteSpace: 'nowrap',

              transition: 'all 0.2s'

            }}>

            <span>{tab.icon}</span> {tab.label}

          </button>

        ))}

      </div>



      {/* Tab Content */}

      {activeTab === 'overview' && (

        <OverviewTab project={project} />
      )}
      {activeTab === 'input' && (
        <InputSourcesPanel />
      )}
      {activeTab === 'analysis' && (
        <>
        <div style={{ marginBottom: '16px', padding: '12px 16px', background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.2)', borderRadius: '6px', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <label style={{ fontSize: '12px', fontWeight: '600', color: '#00ff88' }}>Analysis focus:</label>
          <select value={analysisFocus} onChange={(e) => setAnalysisFocus(e.target.value as any)} style={{ padding: '6px 10px', background: '#0a0a0a', color: '#fff', border: '1px solid #333', borderRadius: '4px', fontSize: '13px' }}>
            <option value='general'>🔍 General Analysis</option>
            <option value='threat-hunt'>🔍 Threat Hunt</option>
            <option value='supply-chain'>📦 Supply Chain</option>
          </select>
          {analysisFocus === 'threat-hunt' && <ThreatHuntPanel />}
          {analysisFocus === 'supply-chain' && <SupplyChainPanel />}
        </div>
        <AnalysisPanel projectId={project.project_id} />
        </>
      )}
      {activeTab === 'agents' && (
        <AgentsPanel 
          runningAgent={runningAgent} 
          onRunAgent={(agent, action, data) => runAgent(agent, action, data)} 
          output={agentOutput} 
        />
      )}
      {activeTab === 'findings' && (

        <FindingsPanel />

      )}
      {activeTab === 'ai-report' && (
        <AIReportPanel projectId={project.project_id} />
      )}

    </div>

  )

}



function OverviewTab({ project }: { project: Project }) {
  const [activity, setActivity] = useState<any[]>([])
  const [realStats, setRealStats] = useState({ findings: 0, critical: 0, high: 0, medium: 0, attack_paths: 0, vulnerabilities: 0 })
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [a, s2] = await Promise.all([
          fetch(`/api/projects/${project.project_id}/activity`).then(r => r.ok ? r.json() : { events: [] }).catch(() => ({ events: [] })),
          fetch(`/api/projects/${project.project_id}/analysis-summary`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
        ])
        if (cancelled) return
        setActivity(a.events || [])
        setRealStats({
          findings: ((s2 as any).code_analysis?.patterns_found || 0) + ((s2 as any).web_analysis?.vulnerabilities || 0),
          critical: (s2 as any).code_analysis?.critical_issues || 0,
          high: 0,
          medium: 0,
          attack_paths: (s2 as any).knowledge_graph?.attack_paths || 0,
          vulnerabilities: (s2 as any).web_analysis?.vulnerabilities || 0,
        })
      } catch (e) { /* keep zeros */ }
    }
    load()
    return () => { cancelled = true }
  }, [project.project_id])
  return (

    <div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>

        <StatCard label="Findings" value={String(realStats.findings || 0)} icon="🎯" color="#00d4ff" />

        <StatCard label="Critical" value={String(realStats.critical || 0)} icon="🚨" color="#ff4444" />

        <StatCard label="High" value={String(realStats.high || 0)} icon="⚠️" color="#ff8844" />

        <StatCard label="Medium" value={String(realStats.medium || 0)} icon="📋" color="#ffaa00" />

      </div>



      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>

        {/* Recent Activity */}

        <div style={{ 

          background: 'rgba(15, 15, 26, 0.95)',

          borderRadius: '16px',

          padding: '24px',

          border: '1px solid rgba(255,255,255,0.05)'

        }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Recent Activity</h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

            {activity.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: '#666', fontSize: '13px' }}>
                <div style={{ fontSize: '32px', marginBottom: '8px' }}>🌱</div>
                <div style={{ fontWeight: '600', marginBottom: '4px', color: '#888' }}>No activity yet</div>
                <div>Run an agent from the Agents tab to populate this feed. Until then, every counter below is 0.</div>
              </div>
            ) : activity.map((item: any, i: number) => (

              <div key={i} style={{

                display: 'flex',

                alignItems: 'center',

                gap: '12px',

                padding: '12px',

                background: 'rgba(0,0,0,0.2)',

                borderRadius: '8px'

              }}>

                <div style={{

                  width: '8px',

                  height: '8px',

                  borderRadius: '50%',

                  background: item.status === 'success' ? '#00ff88' : item.status === 'warning' ? '#ffaa00' : '#00d4ff'

                }} />

                <div style={{ flex: 1 }}>

                  <div style={{ fontSize: '13px', fontWeight: '500' }}>{item.action}</div>

                  <div style={{ fontSize: '11px', color: '#666' }}>{item.details}</div>

                </div>

                <div style={{ fontSize: '11px', color: '#666' }}>{item.time}</div>

              </div>

            ))}

          </div>

        </div>



        {/* Quick Stats */}

        <div style={{ 

          background: 'rgba(15, 15, 26, 0.95)',

          borderRadius: '16px',

          padding: '24px',

          border: '1px solid rgba(255,255,255,0.05)'

        }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Security Score</h3>

          <div style={{ 

            display: 'flex', 

            alignItems: 'center', 

            justifyContent: 'center',

            flexDirection: 'column',

            padding: '20px'

          }}>

            <div style={{

              width: '120px',

              height: '120px',

              borderRadius: '50%',

              background: 'conic-gradient(#00ff88 0deg 70deg, #1a1a2e 70deg 360deg)',

              display: 'flex',

              alignItems: 'center',

              justifyContent: 'center',

              marginBottom: '16px'

            }}>

              <div style={{

                width: '100px',

                height: '100px',

                borderRadius: '50%',

                background: '#0a0a0f',

                display: 'flex',

                alignItems: 'center',

                justifyContent: 'center',

                fontSize: '28px',

                fontWeight: 'bold',

                color: '#00ff88'

              }}>

                72

              </div>

            </div>

            <div style={{ fontSize: '14px', color: '#00ff88', fontWeight: '600' }}>Good Security Posture</div>

            <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>Based on {realStats.findings || 0} findings</div>

          </div>

        </div>

      </div>

    </div>

  )

}



// ============ PHASE 5 PANEL ============

function Phase5Panel({ projectId, selectedAgent, onSelectAgent }: {

  projectId: string;

  selectedAgent: string;

  onSelectAgent: (agent: string) => void;

}) {

  const phase5Agents = [

    { id: 'threat_intelligence', name: '🔍 Threat Intelligence', description: 'YARA rules, IOC enrichment, threat tracking', color: '#ff8844' },

    { id: 'security_operations', name: '🛡️ Security Operations', description: 'SIEM integration, SOAR playbooks', color: '#00d4ff' },

    { id: 'adaptive_defense', name: '⚡ Adaptive Defense', description: 'ML anomaly detection, self-healing', color: '#aa88ff' },

    { id: 'supply_chain', name: '📦 Supply Chain', description: 'SBOM generation, license compliance', color: '#00ff88' },

    { id: 'api_security', name: '🔗 API Security', description: 'OpenAPI analysis, fuzzing, auth testing', color: '#ffaa00' },

  ]



  const [phase5Output, setPhase5Output] = useState<string>('')

  const [runningPhase5, setRunningPhase5] = useState<string | null>(null)



  const runPhase5Agent = async (agentType: string) => {

    setRunningPhase5(agentType)

    setPhase5Output('Initializing Phase 5 agent...')

    try {

      const res = await    fetch(`/api/projects/${projectId}/agents/${agentType.replace(/_/g, '-')}`, {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({ action: 'analyze', input_data: { scope: 'full' } }),

      })

      const data = await res.json()

      setPhase5Output(JSON.stringify(data, null, 2))

    } catch (e) {

      setPhase5Output(`Error: ${e}`)

    } finally {

      setRunningPhase5(null)

    }

  }



  return (

    <div>

      {/* Phase 5 Agent Selection */}

      <div style={{ 

        background: 'linear-gradient(135deg, rgba(255, 136, 68, 0.1), rgba(255, 68, 136, 0.05))',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255, 136, 68, 0.2)',

        marginBottom: '24px'

      }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>

          <span style={{ fontSize: '24px' }}>🚀</span>

          <div>

            <h3 style={{ fontSize: '18px', fontWeight: 'bold', background: 'linear-gradient(90deg, #ff8844, #ff4488)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>

              Phase 5 Security Suite

            </h3>

            <p style={{ fontSize: '12px', color: '#666' }}>Advanced threat hunting, operations, and defense automation</p>

          </div>

        </div>



        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>

          {phase5Agents.map(agent => (

            <button

              key={agent.id}

              onClick={() => { onSelectAgent(agent.id); runPhase5Agent(agent.id) }}

              disabled={runningPhase5 !== null}

              style={{

                background: selectedAgent === agent.id 

                  ? `${agent.color}20` 

                  : 'rgba(0,0,0,0.3)',

                border: `1px solid ${selectedAgent === agent.id ? agent.color : 'rgba(255,255,255,0.1)'}`,

                borderRadius: '12px',

                padding: '16px',

                cursor: runningPhase5 ? 'not-allowed' : 'pointer',

                opacity: runningPhase5 && selectedAgent !== agent.id ? 0.5 : 1,

                transition: 'all 0.2s',

                textAlign: 'center'

              }}

            >

              <div style={{ fontSize: '24px', marginBottom: '8px' }}>{agent.name.split(' ')[0]}</div>

              <div style={{ fontSize: '12px', fontWeight: '600', color: agent.color }}>{agent.name.split(' ').slice(1).join(' ')}</div>

              <div style={{ fontSize: '10px', color: '#666', marginTop: '4px' }}>{agent.description.split(',')[0]}</div>

            </button>

          ))}

        </div>

      </div>



      {/* Phase 5 Details for Selected Agent */}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>

        {/* Agent Info */}

        <div style={{ 

          background: 'rgba(15, 15, 26, 0.95)',

          borderRadius: '16px',

          padding: '24px',

          border: '1px solid rgba(255,255,255,0.05)'

        }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>

            {phase5Agents.find(a => a.id === selectedAgent)?.name || 'Select Agent'}

          </h3>

          <p style={{ fontSize: '13px', color: '#666', marginBottom: '16px' }}>

            {phase5Agents.find(a => a.id === selectedAgent)?.description}

          </p>

          

          <div style={{ 

            background: 'rgba(0,0,0,0.3)', 

            borderRadius: '8px', 

            padding: '16px',

            marginBottom: '16px'

          }}>

            <h4 style={{ fontSize: '13px', fontWeight: '600', marginBottom: '12px', color: '#888' }}>Capabilities</h4>

            {getPhase5Capabilities(selectedAgent).map((cap, i) => (

              <div key={i} style={{

                display: 'flex',

                alignItems: 'center',

                gap: '8px',

                marginBottom: '8px',

                fontSize: '13px',

                color: '#aaa'

              }}>

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

              fontSize: '14px'

            }}

          >

            {runningPhase5 ? '⏳ Running...' : '▶ Run Analysis'}

          </button>

        </div>



        {/* Output */}

        <div style={{ 

          background: 'rgba(10, 10, 15, 0.95)',

          borderRadius: '16px',

          padding: '24px',

          border: '1px solid rgba(255,255,255,0.05)'

        }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Analysis Output</h3>

          <div style={{

            minHeight: '300px',

            maxHeight: '400px',

            overflow: 'auto',

            fontFamily: 'monospace',

            fontSize: '12px',

            color: '#00ff88',

            background: 'rgba(0,0,0,0.3)',

            borderRadius: '8px',

            padding: '16px',

            whiteSpace: 'pre-wrap'

          }}>

            {phase5Output || 'Run an agent to see output here...'}

          </div>

        </div>

      </div>

    </div>

  )

}



function getPhase5Capabilities(agentId: string): string[] {

  switch(agentId) {

    case 'threat_intelligence':

      return ['YARA rule scanning', 'IOC enrichment', 'Threat actor tracking', 'VirusTotal integration', 'Malware analysis']

    case 'security_operations':

      return ['SIEM log analysis', 'SOAR playbook execution', 'Event correlation', 'Incident management', 'Alert triage']

    case 'adaptive_defense':

      return ['ML anomaly detection', 'Behavioral analysis', 'Self-healing automation', 'Threat feed integration', 'Real-time blocking']

    case 'supply_chain':

      return ['SBOM generation', 'Dependency graph analysis', 'License compliance', 'CVE vulnerability scanning', 'Provenance tracking']

    case 'api_security':

      return ['OpenAPI/GraphQL analysis', 'Authentication testing', 'Authorization bypass', 'Rate limiting validation', 'Fuzzing automation']

    default:

      return []

  }

}



// ============ FINDINGS PANEL ============

function FindingsPanel() {

  const [findings] = useState<Finding[]>([])



  const severityColors: Record<string, string> = {

    critical: '#ff4444',

    high: '#ff8844',

    medium: '#ffaa00',

    low: '#00d4ff',

    info: '#888'

  }



  return (

    <div>

      <div style={{ 

        background: 'rgba(15, 15, 26, 0.95)',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255,255,255,0.05)',

        marginBottom: '24px'

      }}>

        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Filters</h3>

        <div style={{ display: 'flex', gap: '12px' }}>

          {['All', 'Critical', 'High', 'Medium', 'Low'].map(filter => (

            <button key={filter} style={{

              background: filter === 'All' ? 'rgba(0, 212, 255, 0.1)' : 'rgba(255,255,255,0.05)',

              border: `1px solid ${filter === 'All' ? '#00d4ff' : 'rgba(255,255,255,0.1)'}`,

              color: filter === 'All' ? '#00d4ff' : '#888',

              padding: '8px 16px',

              borderRadius: '6px',

              cursor: 'pointer',

              fontSize: '12px'

            }}>

              {filter}

            </button>

          ))}

        </div>

      </div>



      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

        {findings.map(finding => (

          <div key={finding.id} style={{

            background: 'rgba(15, 15, 26, 0.95)',

            borderRadius: '12px',

            padding: '20px',

            border: `1px solid ${severityColors[finding.severity]}30`,

            borderLeft: `4px solid ${severityColors[finding.severity]}`

          }}>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>

              <h4 style={{ fontSize: '15px', fontWeight: '600' }}>{finding.title}</h4>

              <span style={{

                background: `${severityColors[finding.severity]}20`,

                color: severityColors[finding.severity],

                fontSize: '11px',

                fontWeight: '600',

                padding: '4px 8px',

                borderRadius: '4px',

                textTransform: 'uppercase'

              }}>

                {finding.severity}

              </span>

            </div>

            <p style={{ fontSize: '13px', color: '#888', marginBottom: '12px' }}>{finding.description}</p>

            <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: '#666' }}>

              <span>📍 {finding.location}</span>

              <span>🔗 {finding.cwe}</span>

              {finding.owasp && <span>📋 OWASP: {finding.owasp.join(', ')}</span>}

            </div>

          </div>

        ))}

      </div>

    </div>

  )

}



// ============ AGENTS PANEL ============

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

              background: 'rgba(15, 15, 26, 0.95)',

              border: `1px solid ${agent.color}40`,

              borderRadius: '12px',

              padding: '16px',

              cursor: runningAgent ? 'not-allowed' : 'pointer',

              opacity: runningAgent ? 0.6 : 1,

              transition: 'all 0.2s',

            }}

            onClick={() => !runningAgent && onRunAgent(agent.id, 'discover', { scope: { domains: ['example.com'] } })}

            onMouseEnter={(e) => {

              if (!runningAgent) {

                e.currentTarget.style.borderColor = agent.color

                e.currentTarget.style.transform = 'translateX(4px)'

              }

            }}

            onMouseLeave={(e) => {

              e.currentTarget.style.borderColor = `${agent.color}40`

              e.currentTarget.style.transform = 'translateX(0)'

            }}>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

                <div style={{ fontSize: '16px', fontWeight: '600', color: agent.color }}>{agent.name}</div>

                {runningAgent === agent.id && (

                  <span style={{ fontSize: '12px', color: '#888', animation: 'pulse 1s infinite' }}>Running...</span>

                )}

              </div>

              <p style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>{agent.description}</p>

            </div>

          ))}

        </div>

        

        <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(0, 212, 255, 0.1)', borderRadius: '8px', fontSize: '12px', color: '#00d4ff' }}>

          💡 Click an agent to run it with default parameters. Results will appear in the output panel.

        </div>

      </div>

      

      {/* Agent Output */}

      <div>

        <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>Agent Output</h3>

        <div style={{

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

  const [isAnalyzing, setIsAnalyzing] = useState(false)

  

  const runCodeAnalysis = async () => {

    setIsAnalyzing(true)

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

    } finally {

      setIsAnalyzing(false)

    }

  }

  

  return (

    <div>

      <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>🔍 Code Analysis (SAST)</h3>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>

        <div>

          <textarea

            value={codeInput}

            onChange={(e) => setCodeInput(e.target.value)}

            style={{

              width: '100%',

              minHeight: '350px',

              background: 'rgba(10, 10, 15, 0.95)',

              border: '1px solid rgba(255,255,255,0.05)',

              borderRadius: '12px',

              padding: '16px',

              color: '#00d4ff',

              fontFamily: 'monospace',

              fontSize: '13px',

              resize: 'vertical',

              outline: 'none'

            }}

            placeholder="Paste code to analyze..."

          />

          <button 

            onClick={runCodeAnalysis} 

            disabled={isAnalyzing}

            style={{

              marginTop: '16px',

              width: '100%',

              background: isAnalyzing 

                ? 'rgba(255,255,255,0.1)' 

                : 'linear-gradient(135deg, #00d4ff, #00ff88)',

              color: isAnalyzing ? '#666' : '#000',

              border: 'none',

              borderRadius: '10px',

              padding: '14px',

              fontWeight: '700',

              cursor: isAnalyzing ? 'not-allowed' : 'pointer',

              fontSize: '14px'

            }}>

            {isAnalyzing ? '⏳ Analyzing...' : '▶ Analyze Code'}

          </button>

        </div>

        

        <div style={{ 

          background: 'rgba(15, 15, 26, 0.95)', 

          borderRadius: '12px', 

          padding: '20px', 

          border: '1px solid rgba(255,255,255,0.05)',

          minHeight: '350px'

        }}>

          <h4 style={{ fontSize: '14px', marginBottom: '16px', color: '#888' }}>Analysis Results</h4>

          {analysisResult ? (

            <div style={{ fontFamily: 'monospace', fontSize: '12px' }}>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px', marginBottom: '16px' }}>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>

                  <div style={{ color: '#666', marginBottom: '4px' }}>Patterns Found</div>

                  <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#00d4ff' }}>{analysisResult.summary?.patterns_found || 0}</div>

                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>

                  <div style={{ color: '#666', marginBottom: '4px' }}>Critical Issues</div>

                  <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff4444' }}>{analysisResult.summary?.critical || 0}</div>

                </div>

              </div>

              

              {analysisResult.patterns?.length > 0 && (

                <div style={{ marginTop: '16px' }}>

                  <div style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>Vulnerabilities:</div>

                  {analysisResult.patterns.map((p: any, i: number) => (

                    <div key={i} style={{

                      background: 'rgba(0,0,0,0.3)',

                      padding: '12px',

                      borderRadius: '8px',

                      marginBottom: '8px',

                      borderLeft: `3px solid ${p.severity === 'critical' ? '#ff4444' : p.severity === 'high' ? '#ff8844' : '#ffaa00'}`

                    }}>

                      <div style={{ fontWeight: '600', color: '#fff', marginBottom: '4px' }}>{p.name}</div>

                      <div style={{ fontSize: '11px', color: '#666' }}>{p.description}</div>

                    </div>

                  ))}

                </div>

              )}

            </div>

          ) : (

            <div style={{ color: '#666', fontSize: '13px', textAlign: 'center', paddingTop: '100px' }}>

              Run analysis to see results

            </div>

          )}

        </div>

      </div>

    </div>

  )

}



// ============ THREAT HUNT VIEW ============

function _ThreatHuntView() {

  const [alerts] = useState<ThreatAlert[]>([

    { id: '1', type: 'malware', severity: 'critical', title: 'Suspicious PowerShell Execution', description: 'Base64 encoded command detected in process creation', timestamp: new Date().toISOString(), iocs: ['192.168.1.105', 'malware.exe'], yara_matches: ['meterpreter', 'covenant'] },

    { id: '2', type: 'network', severity: 'high', title: 'C2 Communication Detected', description: 'Beaconing behavior to known malicious IP', timestamp: new Date(Date.now() - 300000).toISOString(), iocs: ['185.220.101.34'], yara_matches: ['apt_threat'] },

    { id: '3', type: 'anomaly', severity: 'medium', title: 'Unusual Login Pattern', description: 'Login from multiple geographies within 1 hour', timestamp: new Date(Date.now() - 600000).toISOString(), iocs: [], yara_matches: [] },

  ])



  return (

    <div>

      {/* Threat Intel Stats */}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>

        <StatCard label="Active IOCs" value="47" icon="🎯" color="#ff4444" trend="+12" />

        <StatCard label="YARA Rules" value="156" icon="📜" color="#aa88ff" />

        <StatCard label="Threat Feeds" value="8" icon="📡" color="#00d4ff" />

        <StatCard label="IOC Matches" value="3" icon="⚠️" color="#ffaa00" />

      </div>



      {/* Actions */}

      <div style={{ 

        background: 'rgba(15, 15, 26, 0.95)',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255,255,255,0.05)',

        marginBottom: '24px'

      }}>

        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Threat Hunting Actions</h3>

        <div style={{ display: 'flex', gap: '12px' }}>

          <button style={{

            background: 'linear-gradient(135deg, rgba(255, 68, 68, 0.2), rgba(255, 68, 68, 0.1))',

            border: '1px solid #ff4444',

            color: '#ff4444',

            padding: '12px 20px',

            borderRadius: '8px',

            cursor: 'pointer',

            fontSize: '13px',

            fontWeight: '600'

          }}>

            🔍 Scan for IOCs

          </button>

          <button style={{

            background: 'rgba(255,255,255,0.05)',

            border: '1px solid rgba(255,255,255,0.1)',

            color: '#888',

            padding: '12px 20px',

            borderRadius: '8px',

            cursor: 'pointer',

            fontSize: '13px'

          }}>

            📜 Deploy YARA Rules

          </button>

          <button style={{

            background: 'rgba(255,255,255,0.05)',

            border: '1px solid rgba(255,255,255,0.1)',

            color: '#888',

            padding: '12px 20px',

            borderRadius: '8px',

            cursor: 'pointer',

            fontSize: '13px'

          }}>

            📊 Enrich from VirusTotal

          </button>

        </div>

      </div>



      {/* Active Alerts */}

      <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', color: '#888' }}>Active Alerts</h3>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

        {alerts.map(alert => (

          <div key={alert.id} style={{

            background: 'rgba(15, 15, 26, 0.95)',

            borderRadius: '12px',

            padding: '20px',

            border: `1px solid ${alert.severity === 'critical' ? '#ff4444' : alert.severity === 'high' ? '#ff8844' : '#ffaa00'}30`

          }}>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>

                <span style={{ fontSize: '20px' }}>{alert.type === 'malware' ? '🦠' : alert.type === 'network' ? '🌐' : '⚠️'}</span>

                <h4 style={{ fontSize: '15px', fontWeight: '600' }}>{alert.title}</h4>

              </div>

              <span style={{

                background: `${alert.severity === 'critical' ? '#ff4444' : alert.severity === 'high' ? '#ff8844' : '#ffaa00'}20`,

                color: alert.severity === 'critical' ? '#ff4444' : alert.severity === 'high' ? '#ff8844' : '#ffaa00',

                fontSize: '11px',

                fontWeight: '600',

                padding: '4px 8px',

                borderRadius: '4px',

                textTransform: 'uppercase'

              }}>

                {alert.severity}

              </span>

            </div>

            <p style={{ fontSize: '13px', color: '#888', marginBottom: '12px' }}>{alert.description}</p>

            <div style={{ display: 'flex', gap: '16px', fontSize: '12px' }}>

              <span style={{ color: '#666' }}>🕐 {new Date(alert.timestamp).toLocaleString()}</span>

              {alert.iocs && alert.iocs.length > 0 && (

                <span style={{ color: '#00d4ff' }}>📍 IOCs: {alert.iocs.join(', ')}</span>

              )}

              {alert.yara_matches && alert.yara_matches.length > 0 && (

                <span style={{ color: '#aa88ff' }}>📜 YARA: {alert.yara_matches.join(', ')}</span>

              )}

            </div>

          </div>

        ))}

      </div>

    </div>

  )

}







// ============ AUTO AGENT SELECT VIEW ============

function _AutoAgentSelectView() {

  const [selectedVulnType, setSelectedVulnType] = useState<string>('')

  const [scanResults, setScanResults] = useState<any>(null)

  const [isScanning, setIsFullScanning] = useState(false)

  

  const vulnToAgents: Record<string, {primary: string, secondary: string[], description: string, owasp: string[], payloads: string[], severity: string}> = {

    'sql_injection': {

      primary: 'api_security',

      secondary: ['threat_intelligence', 'security_operations'],

      description: 'SQL Injection requires API Security agent with comprehensive SQL injection payloads',

      owasp: ['A01', 'A05'],

      payloads: ["' OR '1'='1", "1' UNION SELECT NULL--", "'; DROP TABLE users; --", "1' ORDER BY 1--", "admin'--"],

      severity: 'critical'

    },

    'xss': {

      primary: 'api_security',

      secondary: ['threat_intelligence'],

      description: 'XSS requires API Security agent for fuzzing with XSS payloads and DOM analysis',

      owasp: ['A05', 'A07'],

      payloads: ['<script>alert(document.domain)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '#\"><img src=x onerror=alert(1)>', 'javascript:alert(document.domain)'],

      severity: 'high'

    },

    'idor': {

      primary: 'api_security',

      secondary: ['threat_intelligence', 'adaptive_defense'],

      description: 'IDOR requires API Security agent for authorization testing and resource enumeration',

      owasp: ['A01'],

      payloads: ['/api/users/123 → /api/users/124', 'POST ID manipulation', 'UUID enumeration', 'HTTP parameter pollution'],

      severity: 'high'

    },

    'ssrf': {

      primary: 'api_security',

      secondary: ['threat_intelligence', 'supply_chain'],

      description: 'SSRF requires API Security agent for protocol testing and internal network probing',

      owasp: ['A01', 'A05', 'A10'],

      payloads: ['http://169.254.169.254/', 'http://localhost:8500', 'file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO', 'dict://localhost:11211/%0astats'],

      severity: 'critical'

    },

    'rce': {

      primary: 'api_security',

      secondary: ['threat_intelligence', 'adaptive_defense', 'security_operations'],

      description: 'RCE requires API Security agent with command injection payloads + Threat Intel for malware analysis',

      owasp: ['A05', 'A08'],

      payloads: ['`whoami`', '$(whoami)', '| whoami', '; whoami', '&& whoami', "'; exec master..xp_cmdshell 'whoami'--", '{{7*7}}', '${exec whoami}'],

      severity: 'critical'

    },

    'xxe': {

      primary: 'api_security',

      secondary: ['supply_chain'],

      description: 'XXE requires API Security agent for XML parsing testing and file read exploitation',

      owasp: ['A05', 'A08'],

      payloads: ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>', '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="expect://ls"/>', 'Billion Laughs attack payload'],

      severity: 'critical'

    },

    'ssti': {

      primary: 'api_security',

      secondary: ['threat_intelligence'],

      description: 'SSTI requires API Security agent with template injection payloads for code execution',

      owasp: ['A05', 'A10'],

      payloads: ['{{7*7}}', '{{config}}', '${7*7}', '${T(SYSTEM)}', '{{request|attr("application")}}'],

      severity: 'critical'

    },

    'graphql': {

      primary: 'api_security',

      secondary: ['supply_chain'],

      description: 'GraphQL requires API Security agent with introspection and batch attack testing',

      owasp: ['A01', 'A05'],

      payloads: [
        // Introspection Attacks
        `{"query":"{ __schema { types { name fields { name } } queryType { name } mutationType { name } } }"}`,
        `{"query":"{ __type(name: \"User\") { name fields { name type { name } } } }"}`,
        `{"query":"{ __schema { mutationType { fields { name description args { name type { name } } } } } }"}`,
        // Batching Attacks (Alias Abuse)
        `{"query":"mutation { login1: login(user: \"admin\", pass: \"1111\") { success } login2: login(user: \"admin\", pass: \"1112\") { success } login3: login(user: \"admin\", pass: \"1113\") { success } }"}`,
        `{"query":"{ a1: user(id: \"1\") { name } a2: user(id: \"1\") { name } a3: user(id: \"1\") { name } a4: user(id: \"1\") { name } a5: user(id: \"1\") { name } }"}`,
        // JSON List Batching
        `[{"query":"mutation { login(user: \"admin\", pass: \"1111\") }"},{"query":"mutation { login(user: \"admin\", pass: \"1112\") }"},{"query":"mutation { login(user: \"admin\", pass: \"1113\") }"}]`,
        // Nested Query DoS
        `{"query":"{ user { friends { friends { friends { friends { name } } } } } }"}`,
        // Circular Reference DoS
        `{"query":"{ user(id: \"1\") { posts { author { posts { author { name } } } } } }"}`,
        // Mutation Injection
        `{"query":"mutation { signIn(login: \"Admin\", password: \"secret\") { success token } }"}`,
        // SQL/NoSQL in GraphQL params
        `{"query":"{ doctors(search: \"{$regex:.*,lastName:Admin}\") { firstName } }"}`,
      ],

      severity: 'high'

    },

    'nosql': {

      primary: 'api_security',

      secondary: ['security_operations'],

      description: 'NoSQL Injection requires API Security agent with MongoDB/Redis operator payloads',

      owasp: ['A05'],

      payloads: ['{"$gt": ""}', '{"$where": "1=1"}', '{"$regex": ".*"}', '{"login": {"$ne": null}}', '{"$expr": {"$gt": [1, 1]}}'],

      severity: 'critical'

    },

    'auth_bypass': {

      primary: 'api_security',

      secondary: ['adaptive_defense', 'security_operations'],

      description: 'Auth bypass requires API Security agent + Adaptive Defense for session analysis',

      owasp: ['A02', 'A07'],

      payloads: ["' OR 1=1--", 'alg: none JWT attack', 'Session fixation', 'OAuth redirect_uri manipulation', 'Basic Auth bypass'],

      severity: 'critical'

    },

    'oauth': {

      primary: 'api_security',

      secondary: ['threat_intelligence'],

      description: 'OAuth vulnerabilities require API Security agent with flow manipulation payloads',

      owasp: ['A01', 'A07'],

      payloads: ['redirect_uri: http://evil.com', 'redirect_uri: null/https://expected.com@evil.com', 'state parameter missing', 'code reuse after logout', 'Scope escalation'],

      severity: 'high'

    },

    'path_traversal': {

      primary: 'api_security',

      secondary: ['threat_intelligence'],

      description: 'Path traversal requires API Security agent for file operation fuzzing',

      owasp: ['A01', 'A05'],

      payloads: ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam', '%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'file:///etc/passwd'],

      severity: 'high'

    },

    'open_redirect': {

      primary: 'api_security',

      secondary: ['threat_intelligence'],

      description: 'Open redirect requires API Security agent for redirect parameter testing',

      owasp: ['A01'],

      payloads: ['https://evil.com', '//evil.com', '///evil.com', 'https://expected.com@evil.com', '\\evil.com'],

      severity: 'medium'

    },

    'business_logic': {

      primary: 'api_security',

      secondary: ['adaptive_defense'],

      description: 'Business logic requires API Security agent + Adaptive Defense for concurrent testing',

      owasp: ['A04', 'A08'],

      payloads: ['Price manipulation: item_price=-100', 'Quantity overflow', 'Race conditions', 'Workflow bypass'],

      severity: 'high'

    },

    'toctou': {

      primary: 'api_security',

      secondary: ['adaptive_defense', 'security_operations'],

      description: 'TOCTOU race conditions require API Security agent + Adaptive Defense for atomicity testing',

      owasp: ['A04', 'A08'],

      payloads: ['Symlink attack during file operations', 'Concurrent authentication requests', 'File race in --skip-existing', 'Double-free after check'],

      severity: 'high'

    },

    'deserialization': {

      primary: 'api_security',

      secondary: ['threat_intelligence'],

      description: 'Deserialization requires API Security agent + Threat Intel for gadget chain analysis',

      owasp: ['A08', 'A05'],

      payloads: ['O:10:"Example":1:{s:3:"cmd";s:8:"whoami";}', 'rO0ABXQAL1VuZGVmaW5lZEv/////dHJhY2U=', '{{obj.__class__.__mro__[1].__subclasses__()}}', 'bash -c {echo,YmFzaCAtaSA+JG1hc2g=}|{base64,-d}|{bash,-i}'],

      severity: 'critical'

    },

    'memory': {

      primary: 'threat_intelligence',

      secondary: ['api_security', 'adaptive_defense'],

      description: 'Memory corruption requires Threat Intelligence agent + Adaptive Defense for fuzzing',

      owasp: ['A08', 'A10'],

      payloads: ["Heap overflow: A'*10000", 'Use-after-free patterns', 'Double-free: free() same twice', 'Format string: %s%s%s%s', 'Integer overflow: large value'],

      severity: 'critical'

    },

    'ci_cd': {

      primary: 'supply_chain',

      secondary: ['security_operations', 'adaptive_defense'],

      description: 'CI/CD security requires Supply Chain agent for pipeline analysis + Security Operations for monitoring',

      owasp: ['A03', 'A08'],

      payloads: ['Secrets in workflow files', 'Untrusted checkout actions', 'Missing security scans', 'Exposed credentials in logs', 'Privilege escalation in pipelines'],

      severity: 'critical'

    },

    'sensitive_data': {

      primary: 'supply_chain',

      secondary: ['security_operations'],

      description: 'Sensitive data exposure requires Supply Chain agent for data classification + Security Operations for monitoring',

      owasp: ['A02', 'A04'],

      payloads: ['Hardcoded API keys', 'Passwords in code', 'Exposed .env files', 'Database credentials in logs', 'AWS keys in source code'],

      severity: 'high'

    }

  }






  const handleScan = async () => {

    if (!selectedVulnType) return

    setIsFullScanning(true)

    setScanResults(null)

    

    // Simulate scanning with auto-recommendation

    setTimeout(() => {

      const config = vulnToAgents[selectedVulnType]

      setScanResults({

        vulnerability: selectedVulnType,

        recommendedAgent: config.primary,

        secondaryAgents: config.secondary,

        description: config.description,

        owaspCategories: config.owasp,

        testPayloads: config.payloads.slice(0, 5),

        severity: config.severity,

        confidence: 'high'

      })

      setIsFullScanning(false)

    }, 1500)

  }



  const agentInfo: Record<string, {name: string, color: string, icon: string, description: string}> = {

    threat_intelligence: { name: '🔍 Threat Intelligence', color: '#ff8844', icon: '🔍', description: 'YARA rules, IOC enrichment, malware analysis' },

    security_operations: { name: '🛡️ Security Operations', color: '#00d4ff', icon: '🛡️', description: 'SIEM integration, SOAR playbooks, alert triage' },

    adaptive_defense: { name: '⚡ Adaptive Defense', color: '#aa88ff', icon: '⚡', description: 'ML anomaly detection, behavioral analysis' },

    supply_chain: { name: '📦 Supply Chain', color: '#00ff88', icon: '📦', description: 'SBOM generation, CVE scanning, license compliance' },

    api_security: { name: '🔗 API Security', color: '#ffaa00', icon: '🔗', description: 'OpenAPI/GraphQL analysis, fuzzing, auth testing' },

  }



  return (

    <div>

      {/* Header */}

      <div style={{ 

        background: 'linear-gradient(135deg, rgba(170, 136, 255, 0.15), rgba(0, 212, 255, 0.1))',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(170, 136, 255, 0.3)',

        marginBottom: '24px'

      }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>

          <span style={{ fontSize: '40px' }}>⚡</span>

          <div>

            <h2 style={{ fontSize: '28px', fontWeight: 'bold', background: 'linear-gradient(90deg, #aa88ff, #00d4ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>

              Auto Agent Selection

            </h2>

            <p style={{ fontSize: '13px', color: '#888' }}>AI-powered agent selection based on vulnerability type - select a bug type and get the perfect agent configuration</p>

          </div>

        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>

          <span style={{ background: 'rgba(170,136,255,0.2)', color: '#aa88ff', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>16 Vulnerability Types</span>

          <span style={{ background: 'rgba(0,212,255,0.2)', color: '#00d4ff', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>5 Phase 5 Agents</span>

          <span style={{ background: 'rgba(0,255,136,0.2)', color: '#00ff88', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>Auto-Configure</span>

        </div>

      </div>



      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>

        {/* Vulnerability Selector */}

        <div style={{ 

          background: 'rgba(15, 15, 26, 0.95)',

          borderRadius: '16px',

          padding: '24px',

          border: '1px solid rgba(255,255,255,0.05)'

        }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', color: '#aa88ff' }}>Select Vulnerability Type</h3>

          

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', marginBottom: '20px' }}>

            {Object.keys(vulnToAgents).map(vuln => (

              <button

                key={vuln}

                onClick={() => setSelectedVulnType(vuln)}

                style={{

                  background: selectedVulnType === vuln ? `${vulnToAgents[vuln].severity === 'critical' ? '#ff4444' : vulnToAgents[vuln].severity === 'high' ? '#ff8844' : '#ffaa00'}25` : 'rgba(0,0,0,0.3)',

                  border: `1px solid ${selectedVulnType === vuln ? (vulnToAgents[vuln].severity === 'critical' ? '#ff4444' : vulnToAgents[vuln].severity === 'high' ? '#ff8844' : '#ffaa00') : 'rgba(255,255,255,0.1)'}`,

                  borderRadius: '8px',

                  padding: '10px',

                  cursor: 'pointer',

                  textAlign: 'left',

                  transition: 'all 0.2s'

                }}

              >

                <span style={{ fontSize: '12px', color: selectedVulnType === vuln ? '#fff' : '#888', fontWeight: selectedVulnType === vuln ? '600' : '400', textTransform: 'capitalize' }}>

                  {vuln.replace(/_/g, ' ')}

                </span>

              </button>

            ))}

          </div>



          <button

            onClick={handleScan}

            disabled={!selectedVulnType || isScanning}

            style={{

              width: '100%',

              background: isScanning ? 'rgba(255,255,255,0.1)' : 'linear-gradient(135deg, #aa88ff, #00d4ff)',

              color: isScanning ? '#666' : '#fff',

              border: 'none',

              borderRadius: '10px',

              padding: '14px',

              fontWeight: '700',

              cursor: isScanning ? 'not-allowed' : 'pointer',

              fontSize: '14px'

            }}

          >

            {isScanning ? '⏳ Analyzing...' : '⚡ Auto-Select Best Agent'}

          </button>

        </div>



        {/* Results Panel */}

        <div style={{ 

          background: 'rgba(15, 15, 26, 0.95)',

          borderRadius: '16px',

          padding: '24px',

          border: '1px solid rgba(255,255,255,0.05)'

        }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', color: '#00d4ff' }}>Agent Configuration</h3>

          

          {scanResults ? (

            <div>

              {/* Primary Agent */}

              <div style={{ 

                background: `${agentInfo[scanResults.recommendedAgent]?.color || '#00d4ff'}15`,

                border: `2px solid ${agentInfo[scanResults.recommendedAgent]?.color || '#00d4ff'}`,

                borderRadius: '12px',

                padding: '16px',

                marginBottom: '16px'

              }}>

                <div style={{ fontSize: '12px', color: '#00ff88', fontWeight: '600', marginBottom: '8px' }}>PRIMARY AGENT (Recommended)</div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>

                  <span style={{ fontSize: '32px' }}>{agentInfo[scanResults.recommendedAgent]?.icon || '🤖'}</span>

                  <div>

                    <div style={{ fontSize: '18px', fontWeight: 'bold', color: agentInfo[scanResults.recommendedAgent]?.color }}>{agentInfo[scanResults.recommendedAgent]?.name || scanResults.recommendedAgent}</div>

                    <div style={{ fontSize: '12px', color: '#888' }}>{agentInfo[scanResults.recommendedAgent]?.description}</div>

                  </div>

                </div>

              </div>



              {/* Secondary Agents */}

              <div style={{ marginBottom: '16px' }}>

                <div style={{ fontSize: '12px', color: '#888', fontWeight: '600', marginBottom: '8px' }}>SECONDARY AGENTS</div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>

                  {scanResults.secondaryAgents.map((agent: string) => (

                    <div key={agent} style={{

                      background: `${agentInfo[agent]?.color || '#888'}15`,

                      border: `1px solid ${agentInfo[agent]?.color || '#888'}40`,

                      borderRadius: '8px',

                      padding: '12px',

                      display: 'flex',

                      alignItems: 'center',

                      gap: '10px'

                    }}>

                      <span style={{ fontSize: '20px' }}>{agentInfo[agent]?.icon || '🤖'}</span>

                      <div>

                        <div style={{ fontSize: '13px', fontWeight: '600', color: agentInfo[agent]?.color }}>{agentInfo[agent]?.name || agent}</div>

                        <div style={{ fontSize: '11px', color: '#666' }}>{agentInfo[agent]?.description}</div>

                      </div>

                    </div>

                  ))}

                </div>

              </div>



              {/* OWASP Categories */}

              <div style={{ marginBottom: '16px' }}>

                <div style={{ fontSize: '12px', color: '#888', fontWeight: '600', marginBottom: '8px' }}>OWASP CATEGORIES</div>

                <div style={{ display: 'flex', gap: '8px' }}>

                  {scanResults.owaspCategories.map((cat: string) => (

                    <span key={cat} style={{ background: 'rgba(255,68,68,0.2)', color: '#ff4444', fontSize: '12px', fontWeight: '600', padding: '4px 12px', borderRadius: '4px' }}>{cat}</span>

                  ))}

                </div>

              </div>



              {/* Severity */}

              <div style={{ marginBottom: '16px' }}>

                <div style={{ fontSize: '12px', color: '#888', fontWeight: '600', marginBottom: '8px' }}>SEVERITY</div>

                <span style={{ 

                  background: scanResults.severity === 'critical' ? 'rgba(255,68,68,0.2)' : scanResults.severity === 'high' ? 'rgba(255,136,68,0.2)' : 'rgba(255,170,0,0.2)',

                  color: scanResults.severity === 'critical' ? '#ff4444' : scanResults.severity === 'high' ? '#ff8844' : '#ffaa00',

                  fontSize: '14px', fontWeight: '700', padding: '6px 16px', borderRadius: '4px', textTransform: 'uppercase'

                }}>

                  {scanResults.severity}

                </span>

              </div>



              {/* Test Payloads */}

              <div>

                <div style={{ fontSize: '12px', color: '#888', fontWeight: '600', marginBottom: '8px' }}>RECOMMENDED PAYLOADS</div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>

                  {scanResults.testPayloads.map((payload: string, i: number) => (

                    <code key={i} style={{ 

                      background: 'rgba(0,0,0,0.4)', 

                      color: '#00d4ff', 

                      fontSize: '11px', 

                      padding: '8px 12px', 

                      borderRadius: '4px',

                      fontFamily: 'monospace',

                      overflow: 'auto',

                      whiteSpace: 'nowrap'

                    }}>{payload}</code>

                  ))}

                </div>

              </div>

            </div>

          ) : (

            <div style={{ color: '#666', fontSize: '13px', textAlign: 'center', paddingTop: '80px' }}>

              Select a vulnerability type and click "Auto-Select Best Agent" to see recommendations

            </div>

          )}

        </div>

      </div>



      {/* Agent Info Grid */}

      <div style={{ marginTop: '24px' }}>

        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', color: '#888' }}>All Available Phase 5 Agents</h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>

          {Object.entries(agentInfo).map(([id, info]) => (

            <div key={id} style={{

              background: 'rgba(15, 15, 26, 0.95)',

              border: `1px solid ${info.color}40`,

              borderRadius: '12px',

              padding: '16px',

              textAlign: 'center'

            }}>

              <div style={{ fontSize: '32px', marginBottom: '8px' }}>{info.icon}</div>

              <div style={{ fontSize: '13px', fontWeight: '600', color: info.color, marginBottom: '4px' }}>{info.name.split(' ')[1]}</div>

              <div style={{ fontSize: '10px', color: '#666' }}>{info.description.split(',')[0]}</div>

            </div>

          ))}

        </div>

      </div>

    </div>

  )

}






// ============ SUPPLY CHAIN VIEW ============

function _SupplyChainView() {

  const [sbom] = useState<SBOMEntry[]>([

    { name: 'lodash', version: '4.17.21', license: 'MIT', vulnerabilities: ['CVE-2021-23337'], risk_score: 7.2 },

    { name: 'axios', version: '0.21.1', license: 'MIT', vulnerabilities: [], risk_score: 2.1 },

    { name: 'express', version: '4.17.1', license: 'MIT', vulnerabilities: ['CVE-2022-24999'], risk_score: 5.5 },

    { name: 'react', version: '17.0.2', license: 'MIT', vulnerabilities: [], risk_score: 1.2 },

    { name: 'ws', version: '7.4.3', license: 'MIT', vulnerabilities: [], risk_score: 0.8 },

  ])



  const getRiskColor = (score: number) => {

    if (score >= 7) return '#ff4444'

    if (score >= 4) return '#ff8844'

    if (score >= 2) return '#ffaa00'

    return '#00ff88'

  }



  return (

    <div>

      {/* Supply Chain Stats */}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>

        <StatCard label="Total Dependencies" value={sbom.length.toString()} icon="📦" color="#00d4ff" />

        <StatCard label="Vulnerable" value={sbom.filter(s => s.vulnerabilities.length > 0).length.toString()} icon="⚠️" color="#ff8844" />

        <StatCard label="High Risk" value={sbom.filter(s => s.risk_score >= 7).length.toString()} icon="🚨" color="#ff4444" />

        <StatCard label="License Issues" value="0" icon="📋" color="#00ff88" />

      </div>



      {/* Actions */}

      <div style={{ 

        background: 'rgba(15, 15, 26, 0.95)',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255,255,255,0.05)',

        marginBottom: '24px'

      }}>

        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>SBOM Actions</h3>

        <div style={{ display: 'flex', gap: '12px' }}>

          <button style={{

            background: 'linear-gradient(135deg, #00d4ff, #00ff88)',

            border: 'none',

            color: '#000',

            padding: '12px 20px',

            borderRadius: '8px',

            cursor: 'pointer',

            fontSize: '13px',

            fontWeight: '700'

          }}>

            📦 Generate SBOM

          </button>

          <button style={{

            background: 'rgba(255,255,255,0.05)',

            border: '1px solid rgba(255,255,255,0.1)',

            color: '#888',

            padding: '12px 20px',

            borderRadius: '8px',

            cursor: 'pointer',

            fontSize: '13px'

          }}>

            📊 Export SPDX

          </button>

          <button style={{

            background: 'rgba(255,255,255,0.05)',

            border: '1px solid rgba(255,255,255,0.1)',

            color: '#888',

            padding: '12px 20px',

            borderRadius: '8px',

            cursor: 'pointer',

            fontSize: '13px'

          }}>

            🔍 Scan Vulnerabilities

          </button>

        </div>

      </div>



      {/* SBOM Table */}

      <div style={{ 

        background: 'rgba(15, 15, 26, 0.95)',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255,255,255,0.05)'

      }}>

        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Software Bill of Materials</h3>

        <table style={{ width: '100%', borderCollapse: 'collapse' }}>

          <thead>

            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>

              <th style={{ textAlign: 'left', padding: '12px', color: '#666', fontSize: '12px', fontWeight: '600' }}>Package</th>

              <th style={{ textAlign: 'left', padding: '12px', color: '#666', fontSize: '12px', fontWeight: '600' }}>Version</th>

              <th style={{ textAlign: 'left', padding: '12px', color: '#666', fontSize: '12px', fontWeight: '600' }}>License</th>

              <th style={{ textAlign: 'left', padding: '12px', color: '#666', fontSize: '12px', fontWeight: '600' }}>Vulnerabilities</th>

              <th style={{ textAlign: 'left', padding: '12px', color: '#666', fontSize: '12px', fontWeight: '600' }}>Risk Score</th>

            </tr>

          </thead>

          <tbody>

            {sbom.map((entry, i) => (

              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>

                <td style={{ padding: '16px 12px', fontSize: '14px', fontWeight: '600' }}>{entry.name}</td>

                <td style={{ padding: '16px 12px', fontSize: '13px', color: '#00d4ff', fontFamily: 'monospace' }}>{entry.version}</td>

                <td style={{ padding: '16px 12px', fontSize: '12px', color: '#888' }}>{entry.license}</td>

                <td style={{ padding: '16px 12px' }}>

                  {entry.vulnerabilities.length > 0 ? (

                    <span style={{ 

                      background: 'rgba(255, 68, 68, 0.1)', 

                      color: '#ff4444', 

                      fontSize: '11px', 

                      fontWeight: '600',

                      padding: '4px 8px',

                      borderRadius: '4px'

                    }}>

                      {entry.vulnerabilities.length} CVE{entry.vulnerabilities.length > 1 ? 's' : ''}

                    </span>

                  ) : (

                    <span style={{ color: '#00ff88', fontSize: '12px' }}>✓ None</span>

                  )}

                </td>

                <td style={{ padding: '16px 12px' }}>

                  <span style={{

                    background: `${getRiskColor(entry.risk_score)}20`,

                    color: getRiskColor(entry.risk_score),

                    fontSize: '13px',

                    fontWeight: '600',

                    padding: '4px 12px',

                    borderRadius: '4px'

                  }}>

                    {entry.risk_score.toFixed(1)}

                  </span>

                </td>

              </tr>

            ))}

          </tbody>

        </table>

      </div>

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

    { id: 'openai', name: 'OpenAI', defaultUrl: 'https://api.openai.com/v1', placeholder: 'sk-...', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo', 'o1', 'o1-mini'] },

    { id: 'anthropic', name: 'Anthropic', defaultUrl: 'https://api.anthropic.com', placeholder: 'sk-ant-api...', models: ['claude-3.5-sonnet-20241022', 'claude-3.5-haiku-20241022', 'claude-3-opus-20240229'] },

    { id: 'groq', name: 'Groq', defaultUrl: 'https://api.groq.com/openai/v1', placeholder: 'gsk_...', models: ['llama-3.3-70b-versatile', 'llama-3.1-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'] },

    { id: 'openrouter', name: 'OpenRouter', defaultUrl: 'https://openrouter.ai/api/v1', placeholder: 'sk-or-...', models: ['openrouter/auto', 'meta-llama/llama-3.3-70b-instruct', 'google/gemini-2.0-flash-exp'] },

    { id: 'ollama', name: 'Ollama (Local)', defaultUrl: 'http://localhost:11434/v1', placeholder: 'not-required', models: ['llama3.3', 'llama3.2', 'mistral', 'codellama'] },

    { id: 'gemini', name: 'Google Gemini', defaultUrl: 'https://generativelanguage.googleapis.com', placeholder: 'AIza...', models: ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-2.0-flash-exp'] },

    { id: 'mistral', name: 'Mistral AI', defaultUrl: 'https://api.mistral.ai/v1', placeholder: '...', models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest'] },

    { id: 'lmstudio', name: 'LM Studio (Local)', defaultUrl: 'http://localhost:1234/v1', placeholder: 'not-required', models: ['llama3.1', 'llama3.2', 'mistral', 'codellama'] },

    { id: 'vllm', name: 'vLLM (Local)', defaultUrl: 'http://localhost:8000/v1', placeholder: 'not-required', models: ['llama3.1', 'mixtral', 'qwen2'] },

    { id: 'opencode', name: 'OpenCode (Self-hosted)', defaultUrl: 'http://localhost:8080', placeholder: 'not-required', models: ['auto'] },

    { id: 'local', name: 'Local/Custom', defaultUrl: 'http://localhost:11434/v1', placeholder: 'not-required', models: ['auto'] },

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

    if (!apiKey && selectedProvider !== 'ollama') {

      setTestStatus({type: 'error', message: 'Please enter an API key'})

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

      

      if (!res.ok) {

        const text = await res.text()

        setTestStatus({type: 'error', message: `❌ HTTP ${res.status}: ${text.substring(0, 200)}`})

        return

      }

      

      const data = await res.json()

      if (data.status === 'ok') {

        setTestStatus({type: 'success', message: `✅ Connected! Model: ${data.model || model}, Latency: ${Math.round(data.latency_ms)}ms`})

      } else {

        setTestStatus({type: 'error', message: `❌ ${data.error}`})

      }

    } catch (e) {

      setTestStatus({type: 'error', message: `❌ Failed: ${e}`})

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

        {/* Left Column */}

        <div style={{ background: 'rgba(15, 15, 26, 0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>

          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '20px' }}>Provider Configuration</h3>

          

          <div style={{ marginBottom: '20px' }}>

            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Provider</label>

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

                fontSize: '14px'

              }}

            >

              {providers.map(p => (

                <option key={p.id} value={p.id}>{p.name}</option>

              ))}

            </select>

          </div>



          <div style={{ marginBottom: '20px' }}>

            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Model</label>

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

                fontFamily: 'monospace'

              }}

            >

              {currentProvider.models.map(m => (

                <option key={m} value={m}>{m}</option>

              ))}

            </select>

          </div>



          <div style={{ marginBottom: '20px' }}>

            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>API Key</label>

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

                fontSize: '14px'

              }}

            />

          </div>



          <div style={{ marginBottom: '24px' }}>

            <label style={{ display: 'block', marginBottom: '8px', color: '#888', fontSize: '13px' }}>Base URL</label>

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

                fontFamily: 'monospace'

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

                cursor: (apiKey || selectedProvider === 'ollama') ? 'pointer' : 'not-allowed',

                fontSize: '13px',

                fontWeight: '600'

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

                cursor: (apiKey || selectedProvider === 'ollama') ? 'pointer' : 'not-allowed',

                fontSize: '13px'

              }}

            >

              {saved ? '✓ Saved!' : 'Save'}

            </button>

          </div>



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



        {/* Right Column */}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          <div style={{ background: 'rgba(15, 15, 26, 0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>

            <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Configured Providers</h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>

              {providers.map(p => {

                const isConfigured = configuredProviders.has(p.id)

                return (

                  <div key={p.id} style={{

                    display: 'flex',

                    justifyContent: 'space-between',

                    alignItems: 'center',

                    padding: '12px',

                    background: selectedProvider === p.id ? 'rgba(0, 212, 255, 0.1)' : 'rgba(0,0,0,0.2)',

                    borderRadius: '8px',

                    border: selectedProvider === p.id ? '1px solid #00d4ff' : '1px solid transparent',

                    cursor: 'pointer'

                  }}

                  onClick={() => setSelectedProvider(p.id)}>

                    <span style={{ fontWeight: '500' }}>{p.name}</span>

                    {isConfigured ? (

                      <span style={{ fontSize: '11px', color: '#00ff88' }}>● Configured</span>

                    ) : (

                      <span style={{ fontSize: '11px', color: '#666' }}>○ Not configured</span>

                    )}

                  </div>

                )

              })}

            </div>

          </div>



          <div style={{ 

            background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(0, 255, 136, 0.05))',

            borderRadius: '16px',

            padding: '24px',

            border: '1px solid rgba(0, 212, 255, 0.2)'

          }}>

            <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>💡 Tips</h3>

            <ul style={{ fontSize: '12px', color: '#888', listStyle: 'none', padding: 0, margin: 0 }}>

              <li style={{ marginBottom: '8px' }}>• Groq offers free tier with llama-3.1 models</li>

              <li style={{ marginBottom: '8px' }}>• OpenRouter provides access to 100+ models</li>

              <li style={{ marginBottom: '8px' }}>• Ollama runs locally - no API key needed</li>

              <li>• API keys are stored in memory only</li>

            </ul>

          </div>

        </div>

      </div>

    </div>

  )

}
// ============ AGENT MODELS UI ============

function AgentModelsView() {
  const [agentModels, setAgentModels] = useState<Record<string, string>>({})
  const [defaults, setDefaults] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string>('')
  const [success, setSuccess] = useState<string>('')

  const fetchModels = async () => {
    try {
      const res = await fetch('/api/agent-models')
      const data = await res.json()
      setAgentModels(data.current || {})
      setDefaults(data.defaults || {})
    } catch (e: any) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchModels() }, [])

  const updateModel = (agent: string, model: string) => {
    setAgentModels(prev => ({ ...prev, [agent]: model }))
  }

  const save = async () => {
    setSaving(true); setError(''); setSuccess('')
    try {
      const res = await fetch('/api/agent-models', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ models: agentModels })
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setSuccess('Models saved to agent_models.json')
      setTimeout(() => setSuccess(''), 3000)
    } catch (e: any) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  const reset = async () => {
    if (!confirm('Reset all agent models to defaults?')) return
    setSaving(true); setError('')
    try {
      const res = await fetch('/api/agent-models/reset', { method: 'POST' })
      const data = await res.json()
      setAgentModels(data.current || {})
      setSuccess('Reset to defaults')
      setTimeout(() => setSuccess(''), 3000)
    } catch (e: any) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div style={{ padding: '32px', color: '#888' }}>Loading agent models...</div>

  const agents = Object.keys(defaults)
  const categories: Record<string, string[]> = {
    'Reconnaissance': ['recon'],
    'Code Analysis': ['code-review', 'dependency'],
    'Threat Modeling': ['threat-modeling', 'threat_intelligence', 'security_operations'],
    'Advanced': ['adaptive_defense', 'supply-chain', 'api_security'],
    'Validation': ['debate']
  }
  const categoryColors: Record<string, string> = {
    'Reconnaissance': '#00d4ff',
    'Code Analysis': '#00ff88',
    'Threat Modeling': '#ff8844',
    'Advanced': '#aa88ff',
    'Validation': '#ffaa00'
  }

  return (
    <div style={{ padding: '0' }}>
      <div style={{ background: 'linear-gradient(135deg, rgba(0,212,255,0.1), rgba(0,255,136,0.05))', borderRadius: '12px', padding: '20px', border: '1px solid rgba(0,212,255,0.2)', marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '4px', color: '#00d4ff' }}>🤖 Agent Models</h2>
            <p style={{ fontSize: '13px', color: '#888' }}>Assign which LLM model each agent uses. Saved to <code style={{ color: '#00ff88' }}>agent_models.json</code>.</p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={reset} disabled={saving} style={{ padding: '8px 16px', background: 'rgba(255,68,68,0.1)', color: '#ff8844', border: '1px solid rgba(255,68,68,0.3)', borderRadius: '6px', cursor: saving ? 'not-allowed' : 'pointer', fontSize: '12px', fontWeight: '600' }}>↺ Reset</button>
            <button onClick={save} disabled={saving} style={{ padding: '8px 20px', background: saving ? 'rgba(255,255,255,0.1)' : 'linear-gradient(135deg, #00d4ff, #00ff88)', color: saving ? '#666' : '#000', border: 'none', borderRadius: '6px', cursor: saving ? 'not-allowed' : 'pointer', fontSize: '12px', fontWeight: '700' }}>{saving ? '⏳ Saving...' : '💾 Save'}</button>
          </div>
        </div>
        {error && <div style={{ marginTop: '12px', padding: '8px 12px', background: 'rgba(255,68,68,0.1)', color: '#ff4444', borderRadius: '6px', fontSize: '12px' }}>⚠️ {error}</div>}
        {success && <div style={{ marginTop: '12px', padding: '8px 12px', background: 'rgba(0,255,136,0.1)', color: '#00ff88', borderRadius: '6px', fontSize: '12px' }}>✓ {success}</div>}
      </div>

      {Object.entries(categories).map(([cat, agentIds]) => {
        const validAgents = agentIds.filter(a => agents.includes(a))
        if (validAgents.length === 0) return null
        const color = categoryColors[cat] || '#888'
        return (
          <div key={cat} style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '14px', fontWeight: '600', color, marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{cat}</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '12px' }}>
              {validAgents.map(agent => {
                const current = agentModels[agent] || defaults[agent] || ''
                const isCustom = current !== (defaults[agent] || '')
                return (
                  <div key={agent} style={{ background: 'rgba(15,15,26,0.95)', border: `1px solid ${isCustom ? color + '60' : 'rgba(255,255,255,0.05)'}`, borderRadius: '10px', padding: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                      <span style={{ fontSize: '13px', fontWeight: '600', color: '#fff' }}>{agent}</span>
                      {isCustom && <span style={{ fontSize: '9px', background: color + '30', color, padding: '2px 6px', borderRadius: '3px', fontWeight: '700' }}>CUSTOM</span>}
                    </div>
                    <input type='text' value={current} onChange={(e) => updateModel(agent, e.target.value)} placeholder={defaults[agent] || 'model-name'} style={{ width: '100%', padding: '8px 10px', background: '#0a0a0a', color: color, border: '1px solid rgba(255,255,255,0.1)', borderRadius: '5px', fontSize: '12px', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
                    <div style={{ fontSize: '10px', color: '#666', marginTop: '6px' }}>default: {defaults[agent] || '—'}</div>
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function LoadingSpinner() {

  return (

    <div style={{ display: 'flex', justifyContent: 'center', padding: '80px' }}>

      <div style={{

        width: '48px',

        height: '48px',

        border: '3px solid rgba(255,255,255,0.1)',

        borderTopColor: '#00d4ff',

        borderRadius: '50%',

        animation: 'spin 1s linear infinite'

      }} />

    </div>

  )

}



export default App

// ============ AI REPORT PANEL ============

function AIReportPanel({ projectId }: { projectId: string }) {
  const [report, setReport] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string>('')
  const [view, setView] = useState<'executive' | 'technical' | 'full'>('full')
  const [stats, setStats] = useState<any>(null)

  useEffect(() => {
    fetch(`/api/projects/${projectId}/analysis-summary`).then(r => r.json()).then(setStats).catch(() => {})
  }, [projectId])

  const generate = async () => {
    setLoading(true); setError(''); setReport('')
    try {
      const res = await fetch(`/api/projects/${projectId}/report`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ view }),
      })
      const data = await res.json()
      if (data.status === 'error') { setError(data.error || 'Report failed'); return }
      setReport(data.report_markdown || '')
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }

  const download = () => {
    const blob = new Blob([report], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url
    a.download = `sentinel-x-report-${projectId}.md`; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <div style={{ background: 'linear-gradient(135deg, rgba(170,136,255,0.1), rgba(0,212,255,0.05))', borderRadius: '12px', padding: '20px', border: '1px solid rgba(170,136,255,0.2)', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '4px' }}><span style={{ background: 'linear-gradient(90deg, #aa88ff, #00d4ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>📝 AI Report</span></h2>
            <p style={{ fontSize: '13px', color: '#888' }}>The configured model writes a Blank.md report from the findings it thinks are worth reporting to the company.</p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <select value={view} onChange={e => setView(e.target.value as any)} style={{ padding: '8px 12px', background: '#0a0a0a', color: '#fff', border: '1px solid #333', borderRadius: '6px', fontSize: '12px' }}>
              <option value='executive'>Executive</option>
              <option value='technical'>Technical</option>
              <option value='full'>Full</option>
            </select>
            <button onClick={generate} disabled={loading} style={{ padding: '8px 20px', background: loading ? 'rgba(255,255,255,0.1)' : 'linear-gradient(135deg, #aa88ff, #00d4ff)', color: loading ? '#666' : '#fff', border: 'none', borderRadius: '6px', cursor: loading ? 'not-allowed' : 'pointer', fontSize: '12px', fontWeight: '700' }}>
              {loading ? '⏳ Writing...' : '✨ Generate'}
            </button>
            {report && (
              <button onClick={download} style={{ padding: '8px 16px', background: 'rgba(0,255,136,0.1)', color: '#00ff88', border: '1px solid rgba(0,255,136,0.3)', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' }}>
                ⬇ Download .md
              </button>
            )}
          </div>
        </div>
        {stats && (
          <div style={{ display: 'flex', gap: '16px', marginTop: '12px', fontSize: '12px', color: '#888' }}>
            <span>🎯 {stats.code_analysis?.patterns_found || 0} code patterns</span>
            <span>🌐 {stats.web_analysis?.vulnerabilities || 0} web vulns</span>
            <span>🛡️ {stats.knowledge_graph?.attack_paths || 0} attack paths</span>
          </div>
        )}
        {error && <div style={{ marginTop: '12px', padding: '8px 12px', background: 'rgba(255,68,68,0.1)', color: '#ff4444', borderRadius: '6px', fontSize: '12px' }}>⚠️ {error}</div>}
      </div>
      <div style={{ background: 'rgba(10,10,15,0.95)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '12px', padding: '20px', minHeight: '400px' }}>
        {report ? (
          <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'ui-monospace, SFMono-Regular, monospace', fontSize: '13px', color: '#e0e0e0', lineHeight: '1.6', margin: 0 }}>{report}</pre>
        ) : (
          <div style={{ textAlign: 'center', padding: '80px 20px', color: '#666' }}>
            <div style={{ fontSize: '48px', marginBottom: '12px' }}>📝</div>
            <div style={{ fontSize: '14px', marginBottom: '8px', color: '#888' }}>No report yet</div>
            <div style={{ fontSize: '12px' }}>Click <span style={{ color: '#aa88ff', fontWeight: '600' }}>Generate</span> to have the model draft a Blank.md report from the project's findings.</div>
          </div>
        )}
      </div>
    </div>
  )
}

