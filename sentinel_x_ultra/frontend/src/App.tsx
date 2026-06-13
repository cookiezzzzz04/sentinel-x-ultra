import { useState, useEffect } from 'react';

import { InputSourcesPanel, ThreatHuntPanel, SupplyChainPanel } from './panel_components';
import { CreateProjectWizard } from './components/CreateProjectWizard';
import { useActivityStream, typeIcons } from './components/ActivityCenter';
import type { ActivityEvent } from './components/ActivityCenter';
import { ProxyMonitor } from './components/ProxyMonitor';
import { ToolRunnerPanel } from './components/ToolRunnerPanel';
import { ModelManagementUI } from './components/ModelManagementUI';
import './index.css';
import { ExecutionMonitor } from './components/ExecutionMonitor';

// Extracted components
import type { Project, HealthStatus } from './components/types';
import { NavItem } from './components/NavItem';
import { DashboardView } from './components/DashboardView';
import { ProjectView } from './components/ProjectView';
import { FindingsPanel } from './components/FindingsPanel';
import { AgentsPanel } from './components/AgentsPanel';
import { AnalysisPanel } from './components/AnalysisPanel';
import { Phase5Panel } from './components/Phase5Panel';
import { ThreatHuntView } from './components/ThreatHuntView';
import { SetupView } from './components/SetupView';
import { BugBountyPanel } from './components/BugBountyPanel';
import { AIReportPanel } from './components/AIReportPanel';
import { LoadingSpinner } from './components/LoadingSpinner';
import { useMediaQuery } from './hooks/useMediaQuery';

// ============ MAIN APP ============

function App() {
  const [view, setView] = useState<'dashboard' | 'models' | 'settings' | 'execution'>('dashboard');
  const [projects, setProjects] = useState<Project[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [isFullScanning, setIsFullScanning] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [pendingProjectName, setPendingProjectName] = useState('');
  const [activityOpen, setActivityOpen] = useState(false);
  const [monitorOpen, setMonitorOpen] = useState(false);

  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [currentProjectType, setCurrentProjectType] = useState<string | null>(null);

  const [configuredProviders, setConfiguredProviders] = useState<Set<string>>(new Set());

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const isCompactScreen = useMediaQuery('(max-width: 1024px)');

  // Auto-collapse sidebar on smaller screens
  useEffect(() => {
    if (isCompactScreen) {
      setSidebarCollapsed(true);
    }
  }, [isCompactScreen]);

  const [notifications, setNotifications] = useState<
    { id: string; message: string; type: string }[]
  >([]);

  const fetchConfiguredProviders = async () => {
    try {
      const res = await fetch('/api/config/providers');

      const data = await res.json();

      if (data.providers) {
        setConfiguredProviders(new Set(data.providers));
      }
    } catch (e) {
      console.error('Failed to fetch configured providers:', e);
    }
  };

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health');

      const data = await res.json();

      setHealth(data);
    } catch (e) {
      console.error('Failed to fetch health:', e);
    }
  };

  const fetchProjects = async () => {
    try {
      const res = await fetch('/api/projects');

      const data = await res.json();

      setProjects(data.projects || []);
    } catch (e) {
      console.error('Failed to fetch projects:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Defer to avoid cascading setState warnings
    setTimeout(() => {
      fetchHealth();
      fetchProjects();
      fetchConfiguredProviders();
    }, 0);
  }, []);

  const createProject = async (
    name: string,
    folder?: string,
    target?: string,
    projectType?: string,
  ) => {
    try {
      const body: any = { name };
      if (folder) {
        body.folder = folder;
      }
      if (target) {
        body.target = target;
      }
      if (projectType) {
        body.project_type = projectType;
      }
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      const newProject = {
        project_id: data.project_id,

        name: data.name,

        created_at: new Date().toISOString(),

        findings_count: 0,

        critical_count: 0,

        high_count: 0,
      };

      setProjects([...projects, newProject]);

      addNotification('success', `Project "${name}" created successfully`);
    } catch (e) {
      console.error('Failed to create project:', e);

      addNotification('error', 'Failed to create project');
    }
  };

  const deleteProject = async (projectId: string) => {
    try {
      const res = await fetch(`/api/projects/${projectId}`, { method: 'DELETE' });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }

      setProjects(projects.filter((p) => p.project_id !== projectId));

      if (currentProject?.project_id === projectId) {
        setCurrentProject(null);

        setView('dashboard');
      }

      addNotification('info', 'Project deleted');
    } catch (e) {
      console.error('Failed to delete project:', e);
      addNotification('error', 'Failed to delete project');
    }
  };

  const { events: activityEvents } = useActivityStream(currentProject?.project_id);

  const addNotification = (type: string, message: string) => {
    const id = Date.now().toString();

    setNotifications((prev) => [...prev, { id, message, type }]);

    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    }, 4000);
  };

  // Fetch project type when opening a project
  useEffect(() => {
    if (currentProject) {
      fetch('/api/projects/' + currentProject.project_id)
        .then((r) => r.json())
        .then((data) => setCurrentProjectType(data.project_type || 'bug-bounty'))
        .catch(() => setCurrentProjectType('bug-bounty'));
    } else {
      Promise.resolve().then(() => setCurrentProjectType(null));
    }
  }, [currentProject]);

  return (
    <div
      style={{
        minHeight: '100vh',

        background: 'linear-gradient(135deg, #0a0a0f 0%, #0f0f1a 50%, #0a0a0f 100%)',

        color: '#fff',

        display: 'flex',

        fontSize: '13px',
      }}
    >
      {/* Notifications Toast */}

      <div
        style={{
          position: 'fixed',

          top: '20px',

          right: '20px',

          zIndex: 1000,

          display: 'flex',

          flexDirection: 'column',

          gap: '8px',
        }}
      >
        {notifications.map((n) => (
          <div
            key={n.id}
            style={{
              background:
                n.type === 'success' ? '#00ff88' : n.type === 'error' ? '#ff4444' : '#00d4ff',

              color: '#000',

              padding: '12px 20px',

              borderRadius: '8px',

              fontWeight: '600',

              fontSize: '13px',

              boxShadow: '0 4px 20px rgba(0,0,0,0.3)',

              animation: 'slideIn 0.3s ease',
            }}
          >
            {n.message}
          </div>
        ))}
      </div>

      {/* Sidebar */}

      <aside
        style={{
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

          zIndex: 100,
        }}
      >
        {/* Logo */}
        <div
          style={{
            padding: '20px',

            borderBottom: '1px solid rgba(255,255,255,0.05)',

            display: 'flex',

            alignItems: 'center',

            gap: '12px',

            overflow: 'hidden',
          }}
        >
          <div
            style={{
              fontSize: '28px',

              flexShrink: 0,
            }}
          >
            🛡️
          </div>

          {!sidebarCollapsed && (
            <div style={{ overflow: 'hidden' }}>
              <h1
                style={{
                  fontSize: '16px',

                  fontWeight: 'bold',

                  background: 'linear-gradient(90deg, #00d4ff, #00ff88)',

                  WebkitBackgroundClip: 'text',

                  WebkitTextFillColor: 'transparent',

                  whiteSpace: 'nowrap',
                }}
              >
                SENTINEL-X ULTRA
              </h1>
            </div>
          )}
        </div>
        {/* Navigation */}{' '}
        <nav style={{ flex: 1, padding: '16px 12px' }}>
          <NavItem
            icon="📊"
            label="Dashboard"
            active={view === 'dashboard' && !currentProject}
            collapsed={sidebarCollapsed}
            onClick={() => {
              setView('dashboard');
              setCurrentProject(null);
            }}
          />{' '}
          <NavItem
            icon="🤖"
            label="Models"
            active={view === 'models'}
            collapsed={sidebarCollapsed}
            onClick={() => {
              setView('models');
              setCurrentProject(null);
            }}
          />
          <NavItem
            icon="⚙️"
            label="Settings"
            active={view === 'settings'}
            collapsed={sidebarCollapsed}
            onClick={() => {
              setView('settings');
              setCurrentProject(null);
            }}
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

            transition: 'all 0.2s',
          }}
        >
          {sidebarCollapsed ? '→' : '← Collapse'}
        </button>
        {/* Health Status */}
        {!sidebarCollapsed && (
          <div
            style={{
              padding: '16px',

              margin: '12px',

              background: 'rgba(0,255,136,0.1)',

              borderRadius: '8px',

              border: '1px solid rgba(0,255,136,0.2)',
            }}
          >
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

      <main
        style={{
          flex: 1,

          marginLeft: sidebarCollapsed ? '70px' : '260px',
          marginRight: activityOpen ? '420px' : '0px',

          transition: 'margin 0.3s ease',

          minHeight: '100vh',
        }}
      >
        <div
          style={{
            maxWidth: '1050px',
            margin: '0 auto',
          }}
        >
          {/* Header */}

          <header
            style={{
              padding: '10px 16px',

              borderBottom: '1px solid rgba(255,255,255,0.05)',

              display: 'flex',

              justifyContent: 'space-between',

              alignItems: 'center',

              background: 'rgba(10, 10, 15, 0.8)',

              backdropFilter: 'blur(10px)',

              position: 'sticky',

              top: 0,

              zIndex: 50,
            }}
          >
            {' '}
            <div>
              <h2 style={{ fontSize: '15px', fontWeight: 'bold', marginBottom: '2px' }}>
                {currentProject ? currentProject.name : 'Security Dashboard'}
              </h2>
              <p style={{ fontSize: '11px', color: '#666' }}>
                {currentProject
                  ? `Project ID: ${currentProject.project_id}`
                  : 'Manage projects and run security analysis'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <button
                onClick={() => setMonitorOpen(!monitorOpen)}
                style={{
                  background: monitorOpen
                    ? 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,136,0.1))'
                    : 'rgba(255,255,255,0.05)',
                  border: monitorOpen
                    ? '1px solid rgba(0,212,255,0.3)'
                    : '1px solid rgba(255,255,255,0.1)',
                  color: monitorOpen ? '#00d4ff' : '#888',
                  padding: '10px 16px',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  fontSize: '13px',
                  transition: 'all 0.2s',
                }}
              >
                {monitorOpen ? '📡' : '📡'}
              </button>
              <button
                onClick={() => setActivityOpen(!activityOpen)}
                style={{
                  background: activityOpen
                    ? 'linear-gradient(135deg, rgba(255,136,68,0.2), rgba(255,68,136,0.1))'
                    : 'rgba(255,255,255,0.05)',
                  border: activityOpen
                    ? '1px solid rgba(255,136,68,0.3)'
                    : '1px solid rgba(255,255,255,0.1)',
                  color: activityOpen ? '#ff8844' : '#888',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '12px',
                  transition: 'all 0.2s',
                  position: 'relative',
                }}
              >
                📋
                {activityEvents.filter((e) => e.status === 'running' || e.status === 'processing')
                  .length > 0 && (
                  <span
                    style={{
                      position: 'absolute',
                      top: '-4px',
                      right: '-4px',
                      width: '10px',
                      height: '10px',
                      borderRadius: '50%',
                      background: '#00d4ff',
                      animation: 'pulse 1s infinite',
                    }}
                  />
                )}
              </button>
              <button
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: '#888',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '12px',
                }}
              >
                🔔 0
              </button>

              {currentProjectType === 'bug-bounty' && (
                <button
                  style={{
                    background: 'linear-gradient(135deg, #00d4ff, #00ff88)',

                    border: 'none',

                    color: '#000',

                    padding: '8px 16px',

                    borderRadius: '6px',

                    fontWeight: '700',

                    cursor: 'pointer',

                    fontSize: '12px',
                  }}
                  onClick={async () => {
                    if (!currentProject) {
                      addNotification('error', 'Open a project first');
                      return;
                    }
                    setIsFullScanning(true);
                    try {
                      const res = await fetch(
                        '/api/projects/' + currentProject.project_id + '/full-scan',
                        {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({}),
                        },
                      );
                      if (!res.ok) {
                        throw new Error('HTTP ' + res.status);
                      }
                      const data = await res.json();
                      addNotification(
                        data.findings_total === 0 ? 'info' : 'success',
                        data.findings_total === 0
                          ? 'Full scan complete: no findings across ' +
                              (data.agents_run ?? 0) +
                              ' agents'
                          : 'Full scan complete: ' +
                              data.findings_total +
                              ' findings across ' +
                              (data.agents_run ?? 0) +
                              ' agents',
                      );
                    } catch (e: any) {
                      addNotification('error', 'Scan failed: ' + (e?.message || 'unknown'));
                    } finally {
                      setIsFullScanning(false);
                    }
                  }}
                  disabled={isFullScanning}
                >
                  {isFullScanning ? '\u25cf Scanning...' : '+ Full Scan'}
                </button>
              )}
            </div>
          </header>

          {/* Page Content */}

          <div style={{ padding: '12px 16px' }}>
            {loading ? (
              <LoadingSpinner />
            ) : showWizard ? (
              <CreateProjectWizard
                defaultName={pendingProjectName}
                onComplete={(name, _desc, folder, projectType) => {
                  createProject(name, folder, undefined, projectType);
                  setShowWizard(false);
                  setPendingProjectName('');
                }}
                onCancel={() => {
                  setShowWizard(false);
                  setPendingProjectName('');
                }}
              />
            ) : currentProject ? (
              <ProjectView
                project={currentProject}
                onBack={() => {
                  setCurrentProject(null);
                  setView('dashboard');
                }}
                addNotification={addNotification}
              />
            ) : view === 'settings' ? (
              <SetupView
                configuredProviders={configuredProviders}
                onProviderConfigured={(providerId) => {
                  setConfiguredProviders(new Set([...configuredProviders, providerId]));
                }}
              />
            ) : view === 'models' ? (
              <ModelManagementUI />
            ) : (
              <DashboardView
                projects={projects}
                onCreateProject={(name) => {
                  setPendingProjectName(name);
                  setShowWizard(true);
                }}
                onDeleteProject={deleteProject}
                onOpenProject={(p) => setCurrentProject(p)}
                health={health}
              />
            )}
          </div>
        </div>
      </main>

      {/* Activity Center */}
      <div
        style={{
          position: 'fixed',
          right: activityOpen ? 0 : '-420px',
          top: 0,
          width: '420px',
          height: '100vh',
          background: 'rgba(10, 10, 15, 0.98)',
          borderLeft: '1px solid rgba(255,255,255,0.05)',
          zIndex: 150,
          display: 'flex',
          flexDirection: 'column',
          transition: 'right 0.3s ease',
          backdropFilter: 'blur(10px)',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            flexShrink: 0,
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '12px',
            }}
          >
            <h3
              style={{
                fontSize: '16px',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              📋 AI Activity
              <span style={{ fontSize: '11px', color: '#666', fontWeight: '400' }}>
                {activityEvents.length} event{activityEvents.length !== 1 ? 's' : ''}
              </span>
            </h3>
            <button
              onClick={() => setActivityOpen(false)}
              style={{
                background: 'rgba(255,255,255,0.05)',
                border: 'none',
                color: '#888',
                padding: '6px 12px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '13px',
              }}
            >
              ✕
            </button>
          </div>
          {activityEvents.filter((e) => e.status === 'running' || e.status === 'processing')
            .length > 0 && (
            <div
              style={{
                fontSize: '12px',
                color: '#00d4ff',
                marginBottom: '8px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: '#00d4ff',
                  animation: 'pulse 1s infinite',
                  display: 'inline-block',
                }}
              />
              AI agents actively processing...
            </div>
          )}
        </div>

        {/* Event timeline */}
        <div style={{ flex: 1, overflow: 'auto', padding: '12px' }}>
          {activityEvents.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '48px 20px', color: '#666' }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>📋</div>
              <div
                style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px', color: '#888' }}
              >
                No activity yet
              </div>
              <div style={{ fontSize: '12px' }}>
                Run an agent or scan to see live AI activity here
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
              {[...activityEvents].reverse().map((event) => (
                <div
                  key={event.id}
                  style={{
                    padding: '10px 12px',
                    borderRadius: '8px',
                    background:
                      event.status === 'running' || event.status === 'processing'
                        ? 'rgba(0,212,255,0.05)'
                        : 'transparent',
                    border:
                      event.status === 'running'
                        ? '1px solid rgba(0,212,255,0.1)'
                        : '1px solid transparent',
                    borderLeft:
                      event.status === 'failed'
                        ? '3px solid #ff4444'
                        : event.status === 'completed'
                          ? '3px solid #00ff88'
                          : event.status === 'running' || event.status === 'processing'
                            ? '3px solid #00d4ff'
                            : '3px solid transparent',
                    animation: 'fadeIn 0.2s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                    <span style={{ fontSize: '14px', flexShrink: 0, marginTop: '1px' }}>
                      {event.icon || typeIcons[event.type] || '•'}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        style={{
                          fontSize: '13px',
                          color: '#ccc',
                          lineHeight: '1.4',
                          fontWeight: event.status === 'running' ? '600' : '400',
                        }}
                      >
                        {event.message}
                      </div>
                      {event.details && (
                        <div
                          style={{
                            fontSize: '11px',
                            color: '#888',
                            marginTop: '4px',
                            fontFamily: 'monospace',
                            background: 'rgba(0,0,0,0.2)',
                            padding: '6px 8px',
                            borderRadius: '4px',
                            whiteSpace: 'pre-wrap',
                            maxHeight: '100px',
                            overflow: 'auto',
                          }}
                        >
                          {event.details}
                        </div>
                      )}
                      <div
                        style={{
                          display: 'flex',
                          gap: '8px',
                          marginTop: '4px',
                          alignItems: 'center',
                        }}
                      >
                        <span style={{ fontSize: '10px', color: '#555', fontFamily: 'monospace' }}>
                          {new Date(event.timestamp).toLocaleTimeString('en-US', {
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                          })}
                        </span>
                        <span
                          style={{
                            fontSize: '9px',
                            padding: '1px 6px',
                            borderRadius: '3px',
                            fontWeight: '600',
                            textTransform: 'uppercase',
                            background:
                              event.status === 'completed'
                                ? 'rgba(0,255,136,0.15)'
                                : event.status === 'failed'
                                  ? 'rgba(255,68,68,0.15)'
                                  : event.status === 'running'
                                    ? 'rgba(0,212,255,0.15)'
                                    : 'rgba(255,255,255,0.05)',
                            color:
                              event.status === 'completed'
                                ? '#00ff88'
                                : event.status === 'failed'
                                  ? '#ff4444'
                                  : event.status === 'running'
                                    ? '#00d4ff'
                                    : '#666',
                          }}
                        >
                          {event.status}
                        </span>
                        {event.source && (
                          <span style={{ fontSize: '10px', color: '#666' }}>{event.source}</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid rgba(255,255,255,0.05)',
            fontSize: '10px',
            color: '#555',
            textAlign: 'center',
            flexShrink: 0,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>{activityEvents.filter((e) => e.status === 'running').length} active</span>
          <button
            onClick={() => setActivityOpen(false)}
            style={{
              background: 'rgba(255,255,255,0.05)',
              border: 'none',
              color: '#888',
              padding: '4px 12px',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '10px',
            }}
          >
            Close Panel
          </button>
        </div>
      </div>

      {/* Monitor Overlay */}
      {monitorOpen && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            right: 0,
            width: '700px',
            height: '100vh',
            background: 'rgba(10,10,15,0.98)',
            borderLeft: '1px solid rgba(255,255,255,0.08)',
            zIndex: 200,
            display: 'flex',
            flexDirection: 'column',
            animation: 'slideIn 0.25s ease',
            backdropFilter: 'blur(10px)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '16px 20px',
              borderBottom: '1px solid rgba(255,255,255,0.05)',
            }}
          >
            <span style={{ fontSize: '15px', fontWeight: '600', color: '#888' }}>📡 Monitor</span>
            <button
              onClick={() => setMonitorOpen(false)}
              style={{
                background: 'rgba(255,255,255,0.05)',
                border: 'none',
                color: '#888',
                padding: '6px 12px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '13px',
              }}
            >
              ✕
            </button>
          </div>
          <div style={{ flex: 1, overflow: 'hidden', padding: '16px' }}>
            <ExecutionMonitor
              projectId={currentProject?.project_id}
              compact={false}
              onDockChange={(pos) => localStorage.setItem('execution_dock', pos)}
            />
          </div>
        </div>
      )}

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

        /* ============ RESPONSIVE BREAKPOINTS ============ */          @media (max-width: 1100px) {
          /* Stat cards: 4 columns → 2 columns */
          [style*="grid-template-columns: repeat(4, 1fr)"] {
            grid-template-columns: repeat(2, 1fr) !important;
          }
          /* Activity/score grid: side-by-side → stacked */
          [style*="grid-template-columns: 2fr 1fr"] {
            grid-template-columns: 1fr !important;
          }
          /* Project cards: smaller min width */
          [style*="minmax(260px, 1fr)"] {
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)) !important;
          }
        }

        @media (max-width: 768px) {
          /* Stat cards: 2 columns → 1 column */
          [style*="grid-template-columns: repeat(4, 1fr)"],
          [style*="grid-template-columns: repeat(2, 1fr)"] {
            grid-template-columns: 1fr !important;
          }
          header {
            padding: 10px 16px !important;
          }
        }

      `}</style>
    </div>
  );
}

export default App;
