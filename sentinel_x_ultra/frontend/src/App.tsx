import { useState, useEffect } from 'react'

import { InputSourcesPanel, ThreatHuntPanel, SupplyChainPanel } from './panel_components'
import { CreateProjectWizard } from './components/CreateProjectWizard'
import { ActivityCenter, useActivityStream } from './components/ActivityCenter'
import type { ActivityEvent } from './components/ActivityCenter'
import { ProxyMonitor } from './components/ProxyMonitor'
import { ToolRunnerPanel } from './components/ToolRunnerPanel'
import { ModelManagementUI } from './components/ModelManagementUI'
import { Button } from './components/Button'
import './index.css'
import { ExecutionMonitor } from './components/ExecutionMonitor'
import type { PipelineStage } from './components/PipelineTracker'



// ============ TYPE DEFINITIONS ============

interface Project {

  project_id: string

  name: string

  created_at: string

  project_type?: string

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

}interface Finding {
  id: string
  type: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  title: string
  description: string
  location?: string
  cwe?: string
  owasp?: string[]
}interface ThreatAlert {
  id: string
  type: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
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

  const [view, setView] = useState<'dashboard' | 'models' | 'settings' | 'execution'>('dashboard')
  const [projects, setProjects] = useState<Project[]>([])
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [isFullScanning, setIsFullScanning] = useState(false)
  const [showWizard, setShowWizard] = useState(false)
  const [pendingProjectName, setPendingProjectName] = useState('')
  const [activityOpen, setActivityOpen] = useState(false)

  const [currentProject, setCurrentProject] = useState<Project | null>(null)
  const [currentProjectType, setCurrentProjectType] = useState<string | null>(null)

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



  const createProject = async (name: string, folder?: string, target?: string, projectType?: string) => {
    try {
      const body: any = { name }
      if (folder) body.folder = folder
      if (target) body.target = target
      if (projectType) body.project_type = projectType
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },        body: JSON.stringify(body),

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



    const { events: activityEvents } = useActivityStream(currentProject?.project_id)

  const addNotification = (type: string, message: string) => {

    const id = Date.now().toString()

    setNotifications(prev => [...prev, { id, message, type }])

    setTimeout(() => {

      setNotifications(prev => prev.filter(n => n.id !== id))

    }, 4000)

  }

  // Fetch project type when opening a project
  useEffect(() => {
    if (currentProject) {
      fetch('/api/projects/' + currentProject.project_id)
        .then(r => r.json())
        .then(data => setCurrentProjectType(data.project_type || 'bug-bounty'))
        .catch(() => setCurrentProjectType('bug-bounty'))
    } else {
      setCurrentProjectType(null)
    }
  }, [currentProject])



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
            icon="📡" 
            label="Monitor" 
            active={view === 'execution'} 
            collapsed={sidebarCollapsed}
            onClick={() => setView('execution')}
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

            {currentProjectType === 'bug-bounty' && <button style={{

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
            </button>}

          </div>

        </header>



        {/* Page Content */}

        <div style={{ padding: '32px' }}>

          {loading ? (

            <LoadingSpinner />

          ) : showWizard ? (

            <CreateProjectWizard
              defaultName={pendingProjectName}
              onComplete={(name, _desc, folder, projectType) => {
                createProject(name, folder, undefined, projectType)
                setShowWizard(false)
                setPendingProjectName('')
              }}
              onCancel={() => { setShowWizard(false); setPendingProjectName('') }}
            />

          ) : currentProject ? (

            <ProjectView project={currentProject} onBack={() => { setCurrentProject(null); setView('dashboard') }} addNotification={addNotification} />

          ) : view === 'settings' ? (

            <ModelManagementUI />

          ) : view === 'models' ? (

            <ModelManagementUI />

          ) : (

            <DashboardView
              projects={projects}
              onCreateProject={(name) => { setPendingProjectName(name); setShowWizard(true) }}
              onDeleteProject={deleteProject}
              onOpenProject={(p) => setCurrentProject(p)}
              health={health}
            />

          )}

        </div>

      </main>

      {/* Activity Center */}
      <ActivityCenter
        events={activityEvents}
        isOpen={activityOpen}
        onToggle={() => setActivityOpen(!activityOpen)}
      />


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
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
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

  const [activeTab, setActiveTab] = useState<string>('overview')
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

  const [projectType, setProjectType] = useState<string | null>(null)

  useEffect(() => {
    // Fetch project type from the server
    fetch(`/api/projects/${project.project_id}`).then(r => r.json()).then(data => {
      setProjectType(data.project_type || 'bug-bounty')
    }).catch(() => {})
  }, [project.project_id])

  const isBugBounty = projectType === 'bug-bounty'

  const tabs = [
    { id: 'overview',  label: 'Overview',       icon: '📊', bio: 'Project dashboard, recent activity, and quick actions to start a new assessment.' },
    { id: 'input',     label: 'Input Sources',  icon: '📥', bio: 'Feed the system with code, URLs, folders, Burp Suite history, or natural-language prompts.' },
    { id: 'analysis',  label: 'Analysis',       icon: '🔍', bio: 'Run code review, web testing, threat hunt, and supply-chain analysis from a single workspace. Pick a focus from the dropdown to switch modes.' },
    { id: 'agents',    label: 'Agents',         icon: '🤖', bio: 'Orchestrate the multi-agent framework: recon, code review, threat modeling, debate, remediation, and Phase 5 advanced agents.' },
    { id: 'findings',  label: 'Findings',       icon: '🎯', bio: 'Browse validated findings, view evidence, attack chains, and export reports in the Blank.md shape.' },
    { id: 'ai-report', label: 'AI Report',       icon: '📝', bio: 'Have the configured model write a Blank.md report from the findings it thinks are worth reporting to the company.' },
    { id: 'execution-monitor' as const, label: 'Monitor', icon: '📡', bio: 'Real-time Execution Monitor with live event stream, pipeline tracker, system status, and full execution history.' },
    ...(isBugBounty
      ? [{ id: 'bug-bounty' as const, label: 'Bug Bounty', icon: '🏴', bio: 'Enterprise Bug Bounty System v7.0 with 10 specialized agents and Foundational Principles for professional ethical security research.' }]
      : []
    ),
    ...(!isBugBounty
      ? [
          { id: 'proxy' as const, label: 'Proxy', icon: '🌐', bio: 'Burp-Style Proxy Monitor with live request streaming, inspector, and real-time traffic analysis.' },
          { id: 'tools' as const, label: 'Tools', icon: '🔧', bio: 'Centralized Tool Runner Service for Gobuster, Nmap, FFUF, and other security tools.' },,
    { id: 'execution-monitor' as const, label: 'Monitor', icon: '📡', bio: 'Real-time Execution Monitor with live event stream, pipeline tracker, system status, and full execution history.' },
        ]
      : []
    ),
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

        {tabs.map((tab: any) => (

          <button key={tab.id} onClick={() => setActiveTab((tab as any).id)}

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

        <FindingsPanel projectId={project.project_id} />

      )}
      {activeTab === 'ai-report' && (
        <AIReportPanel projectId={project.project_id} />
      )}
      {activeTab === 'bug-bounty' && (
        <BugBountyPanel projectId={project.project_id} addNotification={addNotification} />
      )}
      {activeTab === 'proxy' && (
        <ProxyMonitor />
      )}
      {activeTab === 'execution-monitor' && (
        <ExecutionMonitor
          projectId={project.project_id}
          onDockChange={(pos) => localStorage.setItem('execution_dock', pos)}
        />
      )}
      {activeTab === 'tools' && (
        <ToolRunnerPanel />
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
        const pf = (s2 as any).project_findings || {};
        setRealStats({
          findings: ((s2 as any).code_analysis?.patterns_found || 0) + ((s2 as any).web_analysis?.vulnerabilities || 0) + (pf.total || 0),
          critical: ((s2 as any).code_analysis?.critical_issues || 0) + (pf.critical || 0),
          high: ((s2 as any).code_analysis?.high_issues || 0) + (pf.high || 0),
          medium: ((s2 as any).code_analysis?.medium_issues || 0) + (pf.medium || 0),
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

          {realStats.findings === 0 ? (
            <div style={{ textAlign: 'center', padding: '32px 0' }}>
              <div style={{ fontSize: '48px', marginBottom: '12px' }}>📊</div>
              <div style={{ fontSize: '14px', color: '#888', fontWeight: '500' }}>No data yet</div>
              <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>Run an agent to generate findings</div>
            </div>
          ) : (() => {
            const score = Math.max(0, 100 - (realStats.critical * 20) - (realStats.high * 5) - (realStats.medium * 2))
            const color = score >= 80 ? '#00ff88' : score >= 50 ? '#ffaa00' : '#ff4444'
            const label = score >= 80 ? 'Good Security Posture' : score >= 50 ? 'Moderate Risk' : 'Poor Security Posture'
            const degrees = (score / 100) * 360
            return (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', padding: '20px' }}>
                <div style={{
                  width: '120px', height: '120px', borderRadius: '50%',
                  background: `conic-gradient(${color} 0deg ${degrees}deg, #1a1a2e ${degrees}deg 360deg)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px'
                }}>
                  <div style={{
                    width: '100px', height: '100px', borderRadius: '50%', background: '#0a0a0f',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '28px', fontWeight: 'bold', color
                  }}>
                    {score}
                  </div>
                </div>
                <div style={{ fontSize: '14px', color, fontWeight: '600' }}>{label}</div>
                <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                  {realStats.critical > 0 && <span style={{ color: '#ff4444', marginRight: '8px' }}>{realStats.critical} critical</span>}
                  {realStats.high > 0 && <span style={{ color: '#ff8844', marginRight: '8px' }}>{realStats.high} high</span>}
                  {realStats.medium > 0 && <span style={{ color: '#ffaa00' }}>{realStats.medium} medium</span>}
                  {realStats.critical === 0 && realStats.high === 0 && realStats.medium === 0 && <span>No issues found</span>}
                </div>
              </div>
            )
          })()}

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

function FindingsPanel({ projectId }: { projectId: string }) {

  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('All');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const res = await fetch(`/api/projects/${projectId}/findings`);
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) setFindings(data.findings || []);
        }
      } catch (e) { /* keep empty */ }
      finally { if (!cancelled) setLoading(false); }
    };
    load();
    return () => { cancelled = true; };
  }, [projectId]);

  const filtered = filter === 'All'
    ? findings
    : findings.filter(f => f.severity?.toUpperCase() === filter.toUpperCase());

  const severityColors: Record<string, string> = {
    CRITICAL: '#ff4444',
    HIGH: '#ff8844',
    MEDIUM: '#ffaa00',
    LOW: '#00d4ff',
    INFO: '#888'
  };

  return (
    <div>
      <div style={{ 
        background: 'rgba(15, 15, 26, 0.95)',
        borderRadius: '16px',
        padding: '24px',
        border: '1px solid rgba(255,255,255,0.05)',
        marginBottom: '24px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: '600' }}>Filters</h3>
          {findings.length > 0 && (
            <span style={{ fontSize: '12px', color: '#888' }}>{findings.length} unique finding{findings.length !== 1 ? 's' : ''}</span>
          )}
        </div>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {['All', 'Critical', 'High', 'Medium', 'Low'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              background: filter === f ? 'rgba(0, 212, 255, 0.1)' : 'rgba(255,255,255,0.05)',
              border: `1px solid ${filter === f ? '#00d4ff' : 'rgba(255,255,255,0.1)'}`,
              color: filter === f ? '#00d4ff' : '#888',
              padding: '8px 16px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '12px',
              transition: 'all 0.2s',
            }}>
              {f}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ padding: '48px', textAlign: 'center', color: '#666' }}>
          <div style={{ width: '32px', height: '32px', border: '3px solid rgba(0,212,255,0.15)', borderTopColor: '#00d4ff', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 16px' }} />
          <div style={{ fontSize: '13px' }}>Loading findings...</div>
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ padding: '48px', textAlign: 'center', color: '#666' }}>
          <div style={{ fontSize: '40px', marginBottom: '12px' }}>🔍</div>
          <div style={{ fontWeight: '600', marginBottom: '4px', color: '#888', fontSize: '15px' }}>No findings yet</div>
          <div style={{ fontSize: '13px' }}>Run agents or the Bug Bounty pipeline to generate findings. Each vulnerability appears here only once, deduplicated by title and target.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filtered.map((finding, idx) => (
            <div key={finding.id || idx} style={{
              background: 'rgba(15, 15, 26, 0.95)',
              borderRadius: '12px',
              padding: '20px',
              border: `1px solid ${(severityColors[finding.severity] || '#888')}30`,
              borderLeft: `4px solid ${severityColors[finding.severity] || '#888'}`,
              transition: 'all 0.2s',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = (severityColors[finding.severity] || '#888'); e.currentTarget.style.transform = 'translateX(4px)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = `${(severityColors[finding.severity] || '#888')}30`; e.currentTarget.style.transform = 'translateX(0)'; }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <h4 style={{ fontSize: '15px', fontWeight: '600' }}>{finding.title}</h4>
                <span style={{
                  background: `${(severityColors[finding.severity] || '#888')}20`,
                  color: severityColors[finding.severity] || '#888',
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
              <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: '#666', flexWrap: 'wrap' }}>
                {finding.target && <span>📍 {finding.target}</span>}
                {finding.cvss && <span>📊 CVSS: {finding.cvss}</span>}
                {finding.source && <span>🔗 Source: {finding.source}</span>}
                {finding.references && finding.references.length > 0 && (
                  <span>📋 {finding.references.join(', ')}</span>
                )}
              </div>
              {finding.steps_to_reproduce && finding.steps_to_reproduce.length > 0 && (
                <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', fontSize: '12px', color: '#aaa' }}>
                  <div style={{ fontWeight: '600', marginBottom: '8px', color: '#00d4ff', fontSize: '11px', textTransform: 'uppercase' }}>Steps to Reproduce</div>
                  {finding.steps_to_reproduce.map((step: any, i: number) => (
                    <div key={i} style={{ marginBottom: '4px', paddingLeft: '8px', borderLeft: '2px solid rgba(0,212,255,0.3)' }}>
                      {i + 1}. {typeof step === 'string' ? step : step.action || step.description || JSON.stringify(step)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
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

                      borderLeft: `3px solid ${p.severity === 'CRITICAL' ? '#ff4444' : p.severity === 'HIGH' ? '#ff8844' : p.severity === 'MEDIUM' ? '#ffaa00' : '#888'}`

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

function _ThreatHuntView() {  const [alerts] = useState<ThreatAlert[]>([
    { id: '1', type: 'malware', severity: 'CRITICAL', title: 'Suspicious PowerShell Execution', description: 'Base64 encoded command detected in process creation', timestamp: new Date().toISOString(), iocs: ['192.168.1.105', 'malware.exe'], yara_matches: ['meterpreter', 'covenant'] },
    { id: '2', type: 'network', severity: 'HIGH', title: 'C2 Communication Detected', description: 'Beaconing behavior to known malicious IP', timestamp: new Date(Date.now() - 300000).toISOString(), iocs: ['185.220.101.34'], yara_matches: ['apt_threat'] },
    { id: '3', type: 'anomaly', severity: 'MEDIUM', title: 'Unusual Login Pattern', description: 'Login from multiple geographies within 1 hour', timestamp: new Date(Date.now() - 600000).toISOString(), iocs: [], yara_matches: [] },
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

            border: `1px solid ${alert.severity === 'CRITICAL' ? '#ff4444' : alert.severity === 'HIGH' ? '#ff8844' : '#ffaa00'}30`

          }}>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>

                <span style={{ fontSize: '20px' }}>{alert.type === 'malware' ? '🦠' : alert.type === 'network' ? '🌐' : '⚠️'}</span>

                <h4 style={{ fontSize: '15px', fontWeight: '600' }}>{alert.title}</h4>

              </div>

              <span style={{                background: `${alert.severity === 'CRITICAL' ? '#ff4444' : alert.severity === 'HIGH' ? '#ff8844' : '#ffaa00'}20`,
                color: alert.severity === 'CRITICAL' ? '#ff4444' : alert.severity === 'HIGH' ? '#ff8844' : '#ffaa00',

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



// ============ BUG BOUNTY PANEL ============

function BugBountyPanel({ projectId, addNotification }: { projectId?: string; addNotification: (type: string, message: string) => void }) {
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
    fetch('/api/bug-bounty/agents').then(r => r.json()).then(d => setAgents(d.agents || [])).catch(() => {});
    fetch('/api/bug-bounty/ethical-rules').then(r => r.json()).then(setEthicalRules).catch(() => {});
    fetch('/api/bug-bounty/system-prompt').then(r => r.json()).then(d => setSystemPrompt(d.principles || '')).catch(() => {});
  }, []);

  const runPipeline = async () => {
    setPipelineRunning(true);
    setPipelineResult(null);
    try {
      const res = await fetch('/api/bug-bounty/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_domain: targetDomain || 'example.com', in_scope: ['example.com'], project_id: projectId }),
      });
      const data = await res.json();
      setPipelineResult(data);
      addNotification(data.status === 'completed' ? 'success' : 'error',
        data.status === 'completed' ? 'Bug Bounty pipeline completed: ' + (data.findings_count || 0) + ' findings' : 'Pipeline failed');
    } catch (e: any) { addNotification('error', 'Pipeline error: ' + String(e)); }
    finally { setPipelineRunning(false); }
  };

  const runUrlParse = async () => {
    if (!urlInput.trim()) return;
    try {
      const res = await fetch('/api/bug-bounty/url-parse', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput }),
      });
      setUrlResult(await res.json());
    } catch (e: any) { addNotification('error', 'URL parse failed: ' + String(e)); }
  };

  const saveWebhookConfig = async () => {
    try {
      const res = await fetch('/api/bug-bounty/webhook/config', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl, enabled: webhookEnabled }),
      });
      const data = await res.json();
      addNotification(data.status === 'ok' ? 'success' : 'error', data.message || 'Webhook config saved');
    } catch (e: any) { addNotification('error', 'Webhook config error: ' + String(e)); }
  };

  const testWebhook = async () => {
    setWebhookTestResult(null);
    try {
      const res = await fetch('/api/bug-bounty/webhook/test', { method: 'POST' });
      const data = await res.json();
      setWebhookTestResult(data);
      addNotification(data.status === 'ok' ? 'success' : 'error',
        data.success ? 'Webhook test sent successfully' : 'Webhook test failed: ' + (data.error || 'unknown'));
    } catch (e: any) { addNotification('error', 'Webhook test error: ' + String(e)); }
  };

  const fetchWebhookLog = async () => {
    try {
      const res = await fetch('/api/bug-bounty/webhook/log?limit=10');
      const data = await res.json();
      setWebhookLog(data.deliveries || []);
    } catch (e: any) { addNotification('error', 'Failed to fetch webhook log: ' + String(e)); }
  };

  const agentIcons: Record<number, string> = { 1: '🌐', 2: '🛡️', 3: '🚮', 4: '🔍', 5: '🧰', 6: '🔌', 7: '✅', 8: '💥', 9: '📊', 10: '📝' };

  return (
    <div>
      {/* Header */}
      <div style={{ background: 'linear-gradient(135deg, rgba(170,136,255,0.15), rgba(0,212,255,0.1))', borderRadius: '16px', padding: '24px', border: '1px solid rgba(170,136,255,0.3)', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>
          <span style={{ fontSize: '40px' }}>🏴</span>
          <div>
            <h2 style={{ fontSize: '24px', fontWeight: 'bold', background: 'linear-gradient(90deg, #aa88ff, #00d4ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Bug Bounty System v7.0
            </h2>
            <p style={{ fontSize: '13px', color: '#888' }}>Enterprise Multi-Agent Bug Bounty & Security Research System - 10 specialized agents with Foundational Principles</p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ background: 'rgba(170,136,255,0.2)', color: '#aa88ff', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>10 Agents</span>
          <span style={{ background: 'rgba(0,212,255,0.2)', color: '#00d4ff', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>Ethical Rules</span>
          <span style={{ background: 'rgba(0,255,136,0.2)', color: '#00ff88', padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }}>Decision Hierarchy</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', marginBottom: '24px' }}>
        {/* 10 Agents Grid */}
        <div style={{ background: 'rgba(15, 15, 26, 0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>10 Specialized Agents</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
            {agents.map((agent: any) => (
              <div key={agent.id} style={{ background: '#1a1a2e', borderRadius: '8px', padding: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontSize: '20px', marginBottom: '4px' }}>{agentIcons[agent.id] || '🤖'}</div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#00d4ff' }}>{agent.name}</div>
                <div style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>{agent.description}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Ethical Rules */}
        <div style={{ background: 'rgba(15, 15, 26, 0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>🛡️ Ethical Rules</h3>
          {ethicalRules ? ethicalRules.rules?.map((level: any, i: number) => (
            <div key={i} style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '11px', fontWeight: '600', color: '#ff8844', marginBottom: '4px' }}>Level {level.level}: {level.category}</div>
              {level.rules?.map((rule: string, j: number) => (
                <div key={j} style={{ fontSize: '11px', color: '#888', paddingLeft: '12px', marginBottom: '2px' }}>{'•'} {rule}</div>
              ))}
            </div>
          )) : <div style={{ fontSize: '12px', color: '#666' }}>Loading ethical rules...</div>}
          {ethicalRules?.principle && (
            <div style={{ marginTop: '12px', padding: '8px', background: 'rgba(255,68,68,0.1)', borderRadius: '6px', fontSize: '11px', color: '#ff4444', fontWeight: '600' }}>
              {ethicalRules.principle}
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Pipeline Runner */}
        <div style={{ background: 'rgba(15, 15, 26, 0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>🚀 Run Full Pipeline</h3>
          <p style={{ fontSize: '12px', color: '#888', marginBottom: '16px' }}>Run all 10 agents in sequence: URL Parser → Policy Enforcer → Scope Guardian → Passive Intel → Active Enum → Vuln Scanner → Validation Engine → Exploitation → Analysis → Report Generation</p>
          <div style={{ marginBottom: '12px' }}>
            <input type='text' value={targetDomain} onChange={e => setTargetDomain(e.target.value)} placeholder='Target domain (e.g. example.com)' style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #333', background: '#1a1a2e', color: '#fff', fontSize: '13px' }} />
          </div>
          <button onClick={runPipeline} disabled={pipelineRunning} style={{
            width: '100%', padding: '14px', borderRadius: '10px', border: 'none',
            background: pipelineRunning ? 'rgba(255,255,255,0.1)' : 'linear-gradient(135deg, #aa88ff, #00d4ff)',
            color: pipelineRunning ? '#666' : '#fff', fontWeight: '700', fontSize: '14px',
            cursor: pipelineRunning ? 'not-allowed' : 'pointer',
          }}>
            {pipelineRunning ? '⏳ Scanning...' : '🚀 Scan'}
          </button>
          {pipelineResult && (
            <div style={{ marginTop: '16px' }}>
              {/* Policy Decision Summary */}
              {pipelineResult.policy_decisions_summary && pipelineResult.policy_decisions_summary.total_evaluated > 0 && (
                <div style={{ background: '#1a1a2e', borderRadius: '12px', padding: '16px', border: '1px solid rgba(255,255,255,0.05)', marginBottom: '12px' }}>
                  <h4 style={{ fontSize: '13px', fontWeight: '600', color: '#aa88ff', marginBottom: '12px' }}>⚖️ Policy Decision Summary</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
                    <div style={{ background: 'rgba(0,255,136,0.1)', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
                      <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#00ff88' }}>{pipelineResult.policy_decisions_summary.allow}</div>
                      <div style={{ fontSize: '11px', color: '#888' }}>ALLOW</div>
                    </div>
                    <div style={{ background: 'rgba(255,170,0,0.1)', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
                      <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ffaa00' }}>{pipelineResult.policy_decisions_summary.review}</div>
                      <div style={{ fontSize: '11px', color: '#888' }}>REVIEW</div>
                    </div>
                    <div style={{ background: 'rgba(255,68,68,0.1)', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
                      <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff4444' }}>{pipelineResult.policy_decisions_summary.reject}</div>
                      <div style={{ fontSize: '11px', color: '#888' }}>REJECT</div>
                    </div>
                    <div style={{ background: 'rgba(0,212,255,0.1)', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
                      <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#00d4ff' }}>{pipelineResult.policy_decisions_summary.avg_compliance_score?.toFixed?.(0) || 'N/A'}</div>
                      <div style={{ fontSize: '11px', color: '#888' }}>Avg Score</div>
                    </div>
                  </div>
                  <div style={{ marginTop: '8px', fontSize: '11px', color: '#666', textAlign: 'center' }}>
                    {pipelineResult.policy_decisions_summary.total_evaluated} total finding{pipelineResult.policy_decisions_summary.total_evaluated !== 1 ? 's' : ''} evaluated
                  </div>
                </div>
              )}

              {/* Individual Policy Decisions */}
              {pipelineResult.policy_decisions && pipelineResult.policy_decisions.length > 0 && (
                <div style={{ maxHeight: '300px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {pipelineResult.policy_decisions.map((pd: any, idx: number) => (
                    <div key={idx} style={{
                      background: '#1a1a2e',
                      borderRadius: '8px',
                      padding: '12px',
                      border: `1px solid ${pd.decision === 'ALLOW' ? 'rgba(0,255,136,0.2)' : pd.decision === 'REVIEW' ? 'rgba(255,170,0,0.2)' : 'rgba(255,68,68,0.2)'}`,
                      borderLeft: `3px solid ${pd.decision === 'ALLOW' ? '#00ff88' : pd.decision === 'REVIEW' ? '#ffaa00' : '#ff4444'}`,
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <div style={{ fontSize: '12px', fontWeight: '600', color: '#fff' }}>{pd.finding_title}</div>
                        <span style={{
                          fontSize: '10px', fontWeight: '700', padding: '2px 8px', borderRadius: '4px',
                          background: pd.decision === 'ALLOW' ? 'rgba(0,255,136,0.15)' : pd.decision === 'REVIEW' ? 'rgba(255,170,0,0.15)' : 'rgba(255,68,68,0.15)',
                          color: pd.decision === 'ALLOW' ? '#00ff88' : pd.decision === 'REVIEW' ? '#ffaa00' : '#ff4444',
                        }}>{pd.decision}</span>
                      </div>
                      <div style={{ display: 'flex', gap: '12px', fontSize: '10px', color: '#888' }}>
                        <span>Score: <span style={{ color: pd.compliance_score >= 80 ? '#00ff88' : pd.compliance_score >= 60 ? '#ffaa00' : '#ff4444' }}>{pd.compliance_score}</span></span>
                        <span>Conf: <span style={{ color: pd.confidence >= 0.8 ? '#00ff88' : pd.confidence >= 0.5 ? '#ffaa00' : '#ff4444' }}>{(pd.confidence * 100).toFixed(0)}%</span></span>
                        <span>Scope: {pd.scope_status}</span>
                        <span>Evidence: {pd.evidence_tier}</span>
                        <span>Impact: {pd.impact_status}</span>
                      </div>
                      {pd.rejection_arguments && pd.rejection_arguments.length > 0 && (
                        <div style={{ marginTop: '6px', fontSize: '10px', color: '#ff8844' }}>
                          ⚠️ {pd.rejection_arguments[0]}
                        </div>
                      )}
                      {pd.policy_citations && pd.policy_citations.length > 0 && (
                        <div style={{ marginTop: '6px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {pd.policy_citations.map((cit: string, ci: number) => (
                            <span key={ci} style={{ fontSize: '9px', background: 'rgba(170,136,255,0.1)', color: '#aa88ff', padding: '1px 6px', borderRadius: '3px' }}>{cit}</span>
                          ))}
                        </div>
                      )}
                      {pd.recommended_next_action && (
                        <div style={{ marginTop: '6px', fontSize: '10px', fontStyle: 'italic', color: '#666' }}>
                          Next: {pd.recommended_next_action}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Unique Findings Summary */}
              {pipelineResult.unique_findings && pipelineResult.unique_findings.length > 0 && (
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '12px', fontWeight: '600', color: '#00d4ff', marginBottom: '8px' }}>
                    🎯 {pipelineResult.findings_count || pipelineResult.unique_findings.length} Unique Finding{(pipelineResult.findings_count || pipelineResult.unique_findings.length) !== 1 ? 's' : ''}
                  </div>
                  {pipelineResult.unique_findings.map((f: any, i: number) => (
                    <div key={i} style={{ background: '#1a1a2e', borderRadius: '8px', padding: '12px', marginBottom: '8px', borderLeft: '3px solid ' + (f.severity === 'CRITICAL' ? '#ff4444' : f.severity === 'HIGH' ? '#ff8844' : f.severity === 'MEDIUM' ? '#ffaa00' : '#00d4ff') }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontSize: '12px', fontWeight: '600' }}>{f.title}</span>
                        <span style={{ fontSize: '10px', color: f.severity === 'CRITICAL' ? '#ff4444' : f.severity === 'HIGH' ? '#ff8844' : '#888', fontWeight: '600' }}>{f.severity}</span>
                      </div>
                      {f.target && <div style={{ fontSize: '10px', color: '#666' }}>📍 {f.target}</div>}
                      {f.cvss && <div style={{ fontSize: '10px', color: '#666' }}>📊 {f.cvss}</div>}
                    </div>
                  ))}
                </div>
              )}
              {/* Raw pipeline JSON (collapsible) */}
              <details style={{ marginTop: '8px' }}>
                <summary style={{ fontSize: '11px', color: '#888', cursor: 'pointer', userSelect: 'none' }}>Raw pipeline JSON</summary>
                <div style={{ marginTop: '8px', padding: '12px', background: '#1a1a2e', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace', color: '#00ff88', whiteSpace: 'pre-wrap', maxHeight: '300px', overflow: 'auto' }}>
                  {JSON.stringify(pipelineResult.summary || pipelineResult, null, 2)}
                </div>
              </details>
            </div>
          )}
        </div>

        {/* URL Parser Tool */}
        <div style={{ background: 'rgba(15, 15, 26, 0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>
          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>🌐 Agent 1: URL Parser</h3>
          <p style={{ fontSize: '12px', color: '#888', marginBottom: '12px' }}>Parse a HackerOne or BugCrowd program URL to extract program intelligence, scope, and policy.</p>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
            <input type="text" value={urlInput} onChange={e => setUrlInput(e.target.value)} placeholder="https://hackerone.com/example" style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #333', background: '#1a1a2e', color: '#fff', fontSize: '12px' }} />
            <button onClick={runUrlParse} disabled={!urlInput.trim()} style={{ padding: '10px 16px', borderRadius: '6px', border: 'none', background: urlInput.trim() ? '#aa88ff' : '#333', color: '#000', cursor: urlInput.trim() ? 'pointer' : 'not-allowed', fontWeight: '600', fontSize: '12px' }}>Parse</button>
          </div>
          {urlResult && (
            <div style={{ maxHeight: '200px', overflow: 'auto', padding: '12px', background: '#1a1a2e', borderRadius: '8px', fontSize: '11px', color: '#00ff88', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
              {JSON.stringify(urlResult, null, 2)}
            </div>
          )}
        </div>
      </div>

      {/* Webhook Configuration */}
      <div style={{ marginTop: '24px', background: 'rgba(15,15,26,0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', cursor: 'pointer' }} onClick={() => setShowWebhookPanel(!showWebhookPanel)}>
          <h3 style={{ fontSize: '16px', fontWeight: '600' }}>🔔 Webhook Notifications</h3>
          <span style={{ fontSize: '12px', color: webhookUrl ? '#00ff88' : '#888' }}>
            {webhookUrl ? 'Connected' : 'Not configured'} {showWebhookPanel ? '▲' : '▼'}
          </span>
        </div>

        {showWebhookPanel && (
          <div>
            <p style={{ fontSize: '12px', color: '#888', marginBottom: '16px' }}>
              Configure a webhook URL to receive real-time notifications when policy decisions are made
              or when the pipeline completes. Fires for every ALLOW/REVIEW/REJECT decision.
            </p>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input
                type="text"
                value={webhookUrl}
                onChange={e => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.example.com/policy-decisions"
                style={{
                  flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #333',
                  background: '#1a1a2e', color: '#fff', fontSize: '12px',
                }}
              />
              <button
                onClick={saveWebhookConfig}
                disabled={!webhookUrl.trim()}
                style={{
                  padding: '10px 16px', borderRadius: '6px', border: 'none',
                  background: webhookUrl.trim() ? '#aa88ff' : '#333',
                  color: webhookUrl.trim() ? '#000' : '#666',
                  cursor: webhookUrl.trim() ? 'pointer' : 'not-allowed',
                  fontWeight: '600', fontSize: '12px',
                }}>
                Save
              </button>
            </div>

            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '12px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#ccc', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={webhookEnabled}
                  onChange={e => setWebhookEnabled(e.target.checked)}
                  style={{ accentColor: '#aa88ff' }}
                />
                Webhook enabled
              </label>
              <button
                onClick={testWebhook}
                disabled={!webhookUrl.trim() || !webhookEnabled}
                style={{
                  padding: '6px 12px', borderRadius: '4px', border: '1px solid #00d4ff',
                  background: 'transparent', color: '#00d4ff', cursor: 'pointer',
                  fontSize: '11px', fontWeight: '600',
                }}>
                Send Test
              </button>
              <button
                onClick={fetchWebhookLog}
                style={{
                  padding: '6px 12px', borderRadius: '4px', border: '1px solid #888',
                  background: 'transparent', color: '#888', cursor: 'pointer',
                  fontSize: '11px', fontWeight: '600',
                }}>
                View Log
              </button>
            </div>

            {/* Test result */}
            {webhookTestResult && (
              <div style={{
                padding: '8px 12px', borderRadius: '6px', marginBottom: '12px',
                fontSize: '11px', fontFamily: 'monospace',
                background: webhookTestResult.success ? 'rgba(0,255,136,0.1)' : 'rgba(255,68,68,0.1)',
                color: webhookTestResult.success ? '#00ff88' : '#ff4444',
              }}>
                {webhookTestResult.success
                  ? `✓ Test delivered: HTTP ${webhookTestResult.status_code}`
                  : `✗ Test failed: ${webhookTestResult.error || 'Unknown error'}`}
              </div>
            )}

            {/* Webhook delivery log */}
            {webhookLog.length > 0 && (
              <div style={{ maxHeight: '150px', overflow: 'auto' }}>
                <div style={{ fontSize: '11px', color: '#666', marginBottom: '6px' }}>Recent deliveries:</div>
                {webhookLog.map((entry: any, i: number) => (
                  <div key={i} style={{
                    display: 'flex', justifyContent: 'space-between', padding: '4px 8px',
                    fontSize: '10px', borderBottom: '1px solid rgba(255,255,255,0.03)',
                    color: entry.success ? '#00ff88' : '#ff4444',
                  }}>
                    <span>{entry.event} — {entry.success ? `HTTP ${entry.status_code}` : entry.error?.slice(0, 40)}</span>
                    <span style={{ color: '#666' }}>{entry.timestamp?.slice(11, 19)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Decision Hierarchy */}
      <div style={{ marginTop: '24px', background: 'rgba(15,15,26,0.95)', borderRadius: '16px', padding: '24px', border: '1px solid rgba(255,255,255,0.05)' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>🎯 Decision Hierarchy (Priority Order)</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
          {[
            { level: 1, title: 'Legal/Ethical', color: '#ff4444', desc: 'NEVER violated, EVER' },
            { level: 2, title: 'Policy & Scope', color: '#ff8844', desc: 'ALWAYS applied' },
            { level: 3, title: 'Validation', color: '#ffaa00', desc: 'STRICTLY enforced' },
            { level: 4, title: 'Report Quality', color: '#00d4ff', desc: 'MAINTAINED' },
            { level: 5, title: 'Efficiency', color: '#888', desc: 'ADJUSTED' },
          ].map(h => (
            <div key={h.level} style={{ background: '#1a1a2e', borderRadius: '8px', padding: '12px', textAlign: 'center', borderLeft: `3px solid ${h.color}` }}>
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>LEVEL {h.level}</div>
              <div style={{ fontSize: '13px', fontWeight: '600', color: h.color, marginBottom: '4px' }}>{h.title}</div>
              <div style={{ fontSize: '10px', color: '#888' }}>{h.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: '12px', padding: '8px 12px', background: 'rgba(255,68,68,0.1)', borderRadius: '6px', fontSize: '11px', color: '#ff4444', fontWeight: '600', textAlign: 'center' }}>
          CRITICAL RULE: Lower levels NEVER override higher levels
        </div>
      </div>
    </div>
  );
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

