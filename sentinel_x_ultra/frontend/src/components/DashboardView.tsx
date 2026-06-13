import { useState } from 'react';
import type { Project, HealthStatus } from './types';
import { StatCard } from './StatCard';

function ProjectCard({
  project,
  onOpen,
  onDelete,
  showDeleteConfirm,
  onConfirmDelete,
  onCancelDelete,
}: {
  project: Project;
  onOpen: () => void;
  onDelete: () => void;
  showDeleteConfirm: boolean;
  onConfirmDelete: () => void;
  onCancelDelete: () => void;
}) {
  return (
    <div
      style={{
        background: 'rgba(15, 15, 26, 0.95)',
        borderRadius: '8px',
        padding: '10px',
        border: '1px solid rgba(255,255,255,0.05)',
        transition: 'all 0.2s',
        cursor: 'pointer',
        position: 'relative',
      }}
      onClick={onOpen}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'rgba(0, 212, 255, 0.3)';
        e.currentTarget.style.transform = 'translateY(-2px)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)';
        e.currentTarget.style.transform = 'translateY(0)';
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '12px',
        }}
      >
        <h3 style={{ fontSize: '14px', fontWeight: '600' }}>{project.name}</h3>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          style={{
            background: 'rgba(255,68,68,0.1)',
            border: 'none',
            color: '#ff4444',
            padding: '6px 12px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
          }}
        >
          Delete
        </button>
      </div>{' '}
      <p style={{ fontSize: '11px', color: '#666', marginBottom: '10px' }}>
        Created{' '}
        {new Date(project.created_at).toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
        })}
      </p>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <span
          style={{
            fontSize: '11px',
            background: 'rgba(0, 212, 255, 0.1)',
            color: '#00d4ff',
            padding: '4px 10px',
            borderRadius: '4px',
            border: '1px solid rgba(0, 212, 255, 0.2)',
          }}
        >
          {project.findings_count || 0} findings
        </span>
        <span
          style={{
            fontSize: '11px',
            background: 'rgba(255, 68, 68, 0.1)',
            color: '#ff4444',
            padding: '4px 10px',
            borderRadius: '4px',
            border: '1px solid rgba(255, 68, 68, 0.2)',
          }}
        >
          {project.critical_count || 0} critical
        </span>
        <span
          style={{
            fontSize: '11px',
            background: 'rgba(0, 255, 136, 0.1)',
            color: '#00ff88',
            padding: '4px 10px',
            borderRadius: '4px',
            border: '1px solid rgba(0, 255, 136, 0.2)',
          }}
        >
          ● Ready
        </span>
      </div>
      <div style={{ display: 'flex', gap: '6px', marginTop: '12px' }}>
        {['P2', 'P3', 'P4', 'P5'].map((phase) => (
          <span
            key={phase}
            style={{
              fontSize: '9px',
              background:
                phase === 'P5'
                  ? 'linear-gradient(135deg, #ff8844, #ff4488)'
                  : 'rgba(255,255,255,0.05)',
              color: phase === 'P5' ? '#fff' : '#666',
              padding: '3px 8px',
              borderRadius: '4px',
              fontWeight: '600',
            }}
          >
            {phase}
          </span>
        ))}
      </div>
      {showDeleteConfirm && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(0,0,0,0.95)',
            borderRadius: '16px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '12px',
          }}
        >
          <p style={{ fontSize: '14px', fontWeight: '600' }}>Delete "{project.name}"?</p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onConfirmDelete();
              }}
              style={{
                background: '#ff4444',
                color: '#fff',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '12px',
              }}
            >
              Confirm
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onCancelDelete();
              }}
              style={{
                background: 'rgba(255,255,255,0.1)',
                color: '#888',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '12px',
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function EmptyState({
  icon,
  title,
  description,
}: {
  icon: string;
  title: string;
  description: string;
}) {
  return (
    <div
      style={{
        textAlign: 'center',
        padding: '48px 24px',
        background: 'rgba(15, 15, 26, 0.95)',
        borderRadius: '12px',
        border: '1px dashed rgba(255,255,255,0.1)',
      }}
    >
      <div style={{ fontSize: '40px', marginBottom: '12px' }}>{icon}</div>
      <h3 style={{ fontSize: '16px', marginBottom: '6px' }}>{title}</h3>
      <p style={{ color: '#666', marginBottom: '16px', fontSize: '13px' }}>{description}</p>
    </div>
  );
}

export function DashboardView({
  projects,
  onCreateProject,
  onDeleteProject,
  onOpenProject,
  health,
}: {
  projects: Project[];
  onCreateProject: (name: string) => void;
  onDeleteProject: (id: string) => void;
  onOpenProject: (project: Project) => void;
  health: HealthStatus | null;
}) {
  const [newProjectName, setNewProjectName] = useState('');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null);

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (newProjectName.trim()) {
      onCreateProject(newProjectName.trim());
      setNewProjectName('');
    }
  };

  const stats = {
    totalFindings: projects.reduce((sum, p) => sum + (p.findings_count || 0), 0),
    criticalIssues: projects.reduce((sum, p) => sum + (p.critical_count || 0), 0),
    activeProjects: projects.length,
    providersActive: health?.providers?.length || 0,
  };

  return (
    <div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '10px',
          marginBottom: '16px',
        }}
      >
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

      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '10px',
          padding: '14px',
          border: '1px solid rgba(255,255,255,0.05)',
          marginBottom: '16px',
        }}
      >
        <form
          onSubmit={handleCreate}
          style={{ display: 'flex', gap: '16px', alignItems: 'center' }}
        >
          <input
            type="text"
            value={newProjectName}
            onChange={(e) => setNewProjectName(e.target.value)}
            placeholder="Enter project name to start security analysis..."
            style={{
              flex: 1,
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '8px',
              padding: '10px 14px',
              color: '#fff',
              fontSize: '13px',
              outline: 'none',
              transition: 'border-color 0.2s',
            }}
            onFocus={(e) => (e.target.style.borderColor = '#00d4ff')}
            onBlur={(e) => (e.target.style.borderColor = 'rgba(255,255,255,0.1)')}
          />
          <button
            type="submit"
            style={{
              background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
              color: '#000',
              border: 'none',
              borderRadius: '8px',
              padding: '10px 20px',
              fontWeight: '700',
              cursor: 'pointer',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <span>+</span> New Project
          </button>
        </form>
      </div>

      <h3 style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px', color: '#888' }}>
        Your Projects
      </h3>

      {projects.length === 0 ? (
        <EmptyState
          icon="🎯"
          title="No projects yet"
          description="Create your first project to start security analysis with AI-powered agents"
        />
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
            gap: '10px',
          }}
        >
          {projects.map((project) => (
            <ProjectCard
              key={project.project_id}
              project={project}
              onOpen={() => onOpenProject(project)}
              onDelete={() => setShowDeleteConfirm(project.project_id)}
              showDeleteConfirm={showDeleteConfirm === project.project_id}
              onConfirmDelete={() => {
                onDeleteProject(project.project_id);
                setShowDeleteConfirm(null);
              }}
              onCancelDelete={() => setShowDeleteConfirm(null)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
