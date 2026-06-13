import { useState, useEffect } from 'react';
import type { Project } from './types';
import { StatCard } from './StatCard';
import { InputSourcesPanel, ThreatHuntPanel, SupplyChainPanel } from '../panel_components';
import { ProxyMonitor } from './ProxyMonitor';
import { ToolRunnerPanel } from './ToolRunnerPanel';
import { ExecutionMonitor } from './ExecutionMonitor';
import { FindingsPanel } from './FindingsPanel';
import { AgentsPanel } from './AgentsPanel';
import { AnalysisPanel } from './AnalysisPanel';
import { Phase5Panel } from './Phase5Panel';
import { BugBountyPanel } from './BugBountyPanel';
import { AIReportPanel } from './AIReportPanel';
import { OverviewChat } from './OverviewChat';

function OverviewTab({ project }: { project: Project }) {
  const [activity, setActivity] = useState<any[]>([]);
  const [realStats, setRealStats] = useState({
    findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    attack_paths: 0,
    vulnerabilities: 0,
  });

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [a, s2] = await Promise.all([
          fetch(`/api/projects/${project.project_id}/activity`)
            .then((r) => (r.ok ? r.json() : { events: [] }))
            .catch(() => ({ events: [] })),
          fetch(`/api/projects/${project.project_id}/analysis-summary`)
            .then((r) => (r.ok ? r.json() : {}))
            .catch(() => ({})),
        ]);
        if (cancelled) return;
        setActivity(a.events || []);
        const pf = (s2 as any).project_findings || {};
        setRealStats({
          findings:
            ((s2 as any).code_analysis?.patterns_found || 0) +
            ((s2 as any).web_analysis?.vulnerabilities || 0) +
            (pf.total || 0),
          critical: ((s2 as any).code_analysis?.critical_issues || 0) + (pf.critical || 0),
          high: ((s2 as any).code_analysis?.high_issues || 0) + (pf.high || 0),
          medium: ((s2 as any).code_analysis?.medium_issues || 0) + (pf.medium || 0),
          attack_paths: (s2 as any).knowledge_graph?.attack_paths || 0,
          vulnerabilities: (s2 as any).web_analysis?.vulnerabilities || 0,
        });
      } catch (e) {
        /* keep zeros */
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [project.project_id]);

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
          label="Findings"
          value={String(realStats.findings || 0)}
          icon="🎯"
          color="#00d4ff"
        />
        <StatCard
          label="Critical"
          value={String(realStats.critical || 0)}
          icon="🚨"
          color="#ff4444"
        />
        <StatCard label="High" value={String(realStats.high || 0)} icon="⚠️" color="#ff8844" />
        <StatCard label="Medium" value={String(realStats.medium || 0)} icon="📋" color="#ffaa00" />
      </div>
      <OverviewChat projectId={project.project_id} />
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px' }}>
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '12px',
            padding: '16px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>
            Recent Activity
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {activity.length === 0 ? (
              <div
                style={{ padding: '24px', textAlign: 'center', color: '#666', fontSize: '13px' }}
              >
                <div style={{ fontSize: '32px', marginBottom: '8px' }}>🌱</div>
                <div style={{ fontWeight: '600', marginBottom: '4px', color: '#888' }}>
                  No activity yet
                </div>
                <div>Run an agent from the Agents tab to populate this feed.</div>
              </div>
            ) : (
              activity.map((item: any, i: number) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    padding: '12px',
                    background: 'rgba(0,0,0,0.2)',
                    borderRadius: '8px',
                  }}
                >
                  <div
                    style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      background:
                        item.status === 'success'
                          ? '#00ff88'
                          : item.status === 'warning'
                            ? '#ffaa00'
                            : '#00d4ff',
                    }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '13px', fontWeight: '500' }}>{item.action}</div>
                    <div style={{ fontSize: '11px', color: '#666' }}>{item.details}</div>
                  </div>
                  <div style={{ fontSize: '11px', color: '#666' }}>{item.time}</div>
                </div>
              ))
            )}
          </div>
        </div>
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '12px',
            padding: '16px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>
            Security Score
          </h3>
          {realStats.findings === 0 ? (
            <div style={{ textAlign: 'center', padding: '32px 0' }}>
              <div style={{ fontSize: '48px', marginBottom: '12px' }}>📊</div>
              <div style={{ fontSize: '14px', color: '#888', fontWeight: '500' }}>No data yet</div>
              <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                Run an agent to generate findings
              </div>
            </div>
          ) : (
            (() => {
              const score = Math.max(
                0,
                100 - realStats.critical * 20 - realStats.high * 5 - realStats.medium * 2,
              );
              const color = score >= 80 ? '#00ff88' : score >= 50 ? '#ffaa00' : '#ff4444';
              const label =
                score >= 80
                  ? 'Good Security Posture'
                  : score >= 50
                    ? 'Moderate Risk'
                    : 'Poor Security Posture';
              const degrees = (score / 100) * 360;
              return (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexDirection: 'column',
                    padding: '20px',
                  }}
                >
                  {' '}
                  <div
                    style={{
                      width: '100px',
                      height: '100px',
                      borderRadius: '50%',
                      background: `conic-gradient(${color} 0deg ${degrees}deg, #1a1a2e ${degrees}deg 360deg)`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      marginBottom: '12px',
                    }}
                  >
                    <div
                      style={{
                        width: '80px',
                        height: '80px',
                        borderRadius: '50%',
                        background: '#0a0a0f',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '22px',
                        fontWeight: 'bold',
                        color,
                      }}
                    >
                      {score}
                    </div>
                  </div>
                  <div style={{ fontSize: '12px', color, fontWeight: '600' }}>{label}</div>
                  <div style={{ fontSize: '11px', color: '#666', marginTop: '4px' }}>
                    {realStats.critical > 0 && (
                      <span style={{ color: '#ff4444', marginRight: '8px' }}>
                        {realStats.critical} critical
                      </span>
                    )}
                    {realStats.high > 0 && (
                      <span style={{ color: '#ff8844', marginRight: '8px' }}>
                        {realStats.high} high
                      </span>
                    )}
                    {realStats.medium > 0 && (
                      <span style={{ color: '#ffaa00' }}>{realStats.medium} medium</span>
                    )}
                    {realStats.critical === 0 && realStats.high === 0 && realStats.medium === 0 && (
                      <span>No issues found</span>
                    )}
                  </div>
                </div>
              );
            })()
          )}
        </div>
      </div>
    </div>
  );
}

export function ProjectView({
  project,
  onBack,
  addNotification,
}: {
  project: Project;
  onBack: () => void;
  addNotification: (type: string, message: string) => void;
}) {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [analysisFocus, setAnalysisFocus] = useState<'general' | 'threat-hunt' | 'supply-chain'>(
    'general',
  );
  const [agentOutput, setAgentOutput] = useState<string>('');
  const [runningAgent, setRunningAgent] = useState<string | null>(null);
  const [selectedPhase5Agent, setSelectedPhase5Agent] = useState<string>('threat_intelligence');

  const runAgent = async (agentType: string, action: string, inputData: any) => {
    setRunningAgent(agentType);
    setAgentOutput('Initializing agent...');
    try {
      const res = await fetch(`/api/projects/${project.project_id}/agents/${agentType}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, input_data: inputData }),
      });
      const data = await res.json();
      setAgentOutput(JSON.stringify(data, null, 2));
      addNotification('success', `${agentType} completed successfully`);
    } catch (e) {
      setAgentOutput(`Error: ${e}`);
      addNotification('error', `Agent ${agentType} failed`);
    } finally {
      setRunningAgent(null);
    }
  };

  const [projectType, setProjectType] = useState<string | null>(null);
  useEffect(() => {
    fetch(`/api/projects/${project.project_id}`)
      .then((r) => r.json())
      .then((data) => setProjectType(data.project_type || 'bug-bounty'))
      .catch(() => {});
  }, [project.project_id]);

  const isBugBounty = projectType === 'bug-bounty';

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: '📊',
      bio: 'Project dashboard, recent activity, and quick actions.',
    },
    ...(isBugBounty
      ? [
          {
            id: 'bug-bounty' as const,
            label: 'Bug Bounty',
            icon: '🏴',
            bio: '10 specialized agents for professional security research.',
          },
        ]
      : []),
    {
      id: 'input',
      label: 'Input Sources',
      icon: '📥',
      bio: 'Feed the system with code, URLs, folders, or prompts.',
    },
    ...(!isBugBounty
      ? [
          {
            id: 'analysis' as const,
            label: 'Analysis',
            icon: '🔍',
            bio: 'Run code review, web testing, threat hunt, and supply-chain analysis.',
          },
        ]
      : []),
    ...(!isBugBounty
      ? [
          {
            id: 'agents' as const,
            label: 'Agents',
            icon: '🤖',
            bio: 'Orchestrate the multi-agent framework.',
          },
        ]
      : []),
    {
      id: 'findings',
      label: 'Findings',
      icon: '🎯',
      bio: 'Browse validated findings, view evidence, attack chains.',
    },
    {
      id: 'ai-report',
      label: 'AI Report',
      icon: '📝',
      bio: 'Have the model write a Blank.md report.',
    },
    ...(!isBugBounty
      ? [
          {
            id: 'proxy' as const,
            label: 'Proxy',
            icon: '🌐',
            bio: 'Burp-Style Proxy Monitor with live request streaming.',
          },
          {
            id: 'tools' as const,
            label: 'Tools',
            icon: '🔧',
            bio: 'Centralized Tool Runner for Gobuster, Nmap, FFUF.',
          },
          {
            id: 'execution-monitor' as const,
            label: 'Monitor',
            icon: '📡',
            bio: 'Real-time Execution Monitor with live event stream.',
          },
        ]
      : []),
  ];

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>
        <button
          onClick={onBack}
          style={{
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.1)',
            color: '#888',
            padding: '8px 12px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
            transition: 'all 0.2s',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = '#00d4ff';
            e.currentTarget.style.color = '#00d4ff';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
            e.currentTarget.style.color = '#888';
          }}
        >
          ← Back
        </button>
        <div>
          <h1 style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '2px' }}>
            {project.name}
          </h1>
          <p style={{ fontSize: '11px', color: '#666' }}>Project ID: {project.project_id}</p>
        </div>
      </div>

      <div
        style={{
          display: 'flex',
          gap: '8px',
          marginBottom: '24px',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          paddingBottom: '16px',
          overflowX: 'auto',
        }}
      >
        {tabs.map((tab: any) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background:
                activeTab === tab.id
                  ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(0, 255, 136, 0.1))'
                  : 'transparent',
              color: activeTab === tab.id ? '#00d4ff' : '#888',
              border:
                activeTab === tab.id ? '1px solid rgba(0, 212, 255, 0.3)' : '1px solid transparent',
              padding: '8px 14px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontWeight: '600',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              whiteSpace: 'nowrap',
              transition: 'all 0.2s',
            }}
          >
            <span>{tab.icon}</span> {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && <OverviewTab project={project} />}
      {activeTab === 'input' && <InputSourcesPanel />}
      {activeTab === 'analysis' && (
        <>
          <div
            style={{
              marginBottom: '12px',
              padding: '8px 12px',
              background: 'rgba(0,255,136,0.06)',
              border: '1px solid rgba(0,255,136,0.2)',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              flexWrap: 'wrap',
            }}
          >
            <label style={{ fontSize: '12px', fontWeight: '600', color: '#00ff88' }}>
              Analysis focus:
            </label>
            <select
              value={analysisFocus}
              onChange={(e) => setAnalysisFocus(e.target.value as any)}
              style={{
                padding: '6px 10px',
                background: '#0a0a0a',
                color: '#fff',
                border: '1px solid #333',
                borderRadius: '4px',
                fontSize: '13px',
              }}
            >
              <option value="general">🔍 General Analysis</option>
              <option value="threat-hunt">🔍 Threat Hunt</option>
              <option value="supply-chain">📦 Supply Chain</option>
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
      {activeTab === 'findings' && <FindingsPanel projectId={project.project_id} />}
      {activeTab === 'ai-report' && <AIReportPanel projectId={project.project_id} />}
      {activeTab === 'bug-bounty' && (
        <BugBountyPanel
          projectId={project.project_id}
          addNotification={addNotification}
          onNavigate={(tab: string) => setActiveTab(tab)}
        />
      )}
      {activeTab === 'proxy' && <ProxyMonitor />}
      {activeTab === 'execution-monitor' && (
        <ExecutionMonitor
          projectId={project.project_id}
          onDockChange={(pos) => localStorage.setItem('execution_dock', pos)}
        />
      )}
      {activeTab === 'tools' && <ToolRunnerPanel />}
    </div>
  );
}
