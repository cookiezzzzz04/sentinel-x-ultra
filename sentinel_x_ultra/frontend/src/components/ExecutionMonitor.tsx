import { useState, useEffect, useRef, useCallback } from 'react';
import { LiveLogStream } from './LiveLogStream';
import type { LogEvent } from './LiveLogStream';
import { PipelineTracker } from './PipelineTracker';
import type { PipelineStage } from './PipelineTracker';
import { StatusIndicator, ProgressBar } from './StatusIndicator';
import type { StatusType } from './StatusIndicator';

// ============ TYPES ============

interface ExecutionStatus {
  total_events: number;
  active_count: number;
  completed_count: number;
  failed_count: number;
  active: LogEvent[];
  latest_completed: LogEvent[];
  latest_failed: LogEvent[];
}

interface SystemStatus {
  active_tasks: number;
  active_descriptions: string[];
  event_type_breakdown: Record<string, number>;
  source_breakdown: Record<string, number>;
  recent_errors: LogEvent[];
}

type DockPosition = 'right' | 'bottom' | 'left' | 'window';
type MonitorTab = 'stream' | 'pipeline' | 'status' | 'history';

// ============ DEFAULT PIPELINE STAGES ============

const DEFAULT_PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 1,
    name: 'URL Parser',
    description: 'Parses HackerOne/BugCrowd URLs',
    status: 'waiting',
    icon: '🌐',
  },
  {
    id: 2,
    name: 'Policy Enforcer',
    description: 'Gatekeeper - reads program policy',
    status: 'waiting',
    icon: '🛡️',
  },
  {
    id: 3,
    name: 'Scope Guardian',
    description: 'Verifies authorized scope boundaries',
    status: 'waiting',
    icon: '🚮',
  },
  {
    id: 4,
    name: 'Passive Intel',
    description: 'Non-intrusive OSINT reconnaissance',
    status: 'waiting',
    icon: '🔍',
  },
  {
    id: 5,
    name: 'Active Enum',
    description: 'Direct interaction to map attack surface',
    status: 'waiting',
    icon: '🧰',
  },
  {
    id: 6,
    name: 'Vuln Scanner',
    description: 'OWASP Top 10 vulnerability testing',
    status: 'waiting',
    icon: '🔌',
  },
  {
    id: 7,
    name: 'Validation Engine',
    description: 'Multi-stage false positive elimination',
    status: 'waiting',
    icon: '✅',
  },
  {
    id: 8,
    name: 'Exploitation',
    description: 'Safe proof-of-concept creation',
    status: 'waiting',
    icon: '💥',
  },
  {
    id: 9,
    name: 'Analysis',
    description: 'CVSS scoring, CWE mapping',
    status: 'waiting',
    icon: '📊',
  },
  {
    id: 10,
    name: 'Report Gen',
    description: 'Professional Blank.md reports',
    status: 'waiting',
    icon: '📝',
  },
];

// ============ EXECUTION MONITOR COMPONENT ============

interface ExecutionMonitorProps {
  projectId?: string;
  dockPosition?: DockPosition;
  onDockChange?: (pos: DockPosition) => void;
  compact?: boolean;
  isDocked?: boolean;
  onClose?: () => void;
}

export function ExecutionMonitor({
  projectId,
  dockPosition = 'right',
  onDockChange,
  compact = false,
  isDocked: _isDocked = false,
  onClose,
}: ExecutionMonitorProps) {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [status, setStatus] = useState<ExecutionStatus | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState<MonitorTab>('stream');
  const [pipelineStages, setPipelineStages] = useState<PipelineStage[]>(DEFAULT_PIPELINE_STAGES);
  const [selectedEvent, setSelectedEvent] = useState<LogEvent | null>(null);
  const [showPipeline, setShowPipeline] = useState(true);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Poll for execution status updates
  useEffect(() => {
    const poll = async () => {
      try {
        const [statusRes, sysRes] = await Promise.all([
          fetch('/api/execution/status'),
          fetch('/api/execution/system-status'),
        ]);
        if (statusRes.ok) {
          setStatus(await statusRes.json());
        }
        if (sysRes.ok) {
          setSystemStatus(await sysRes.json());
        }
      } catch {
        /* ignore */
      }
    };
    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
      }
    };
  }, []);

  // Initial fetch on mount (then WebSocket handles all live updates)
  useEffect(() => {
    const fetchInitial = async () => {
      try {
        const res = await fetch('/api/execution/events/recent?limit=200');
        if (res.ok) {
          const data = await res.json();
          if (data.events && data.events.length > 0) {
            setEvents(data.events);
          }
        }
      } catch {
        /* ignore */
      }
    };
    fetchInitial();
  }, []);

  // WebSocket for live streaming
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsUrl = projectId
          ? `${protocol}//${host}/api/ws/activity?project_id=${projectId}`
          : `${protocol}//${host}/api/ws/activity`;
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => setIsConnected(true);
        ws.onclose = () => {
          setIsConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        };
        ws.onerror = () => ws?.close();
        ws.onmessage = (msg) => {
          try {
            const event = JSON.parse(msg.data) as LogEvent;
            // Dedup by ID - only add if not already in the list
            setEvents((prev) => {
              if (prev.some((e) => e.id === event.id)) {
                return prev;
              }
              const next = [...prev, event];
              return next.length > 500 ? next.slice(-500) : next;
            });
          } catch {
            /* ignore */
          }
        };
      } catch {
        /* ignore */
      }
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      ws?.close();
      wsRef.current = null;
    };
  }, [projectId]);

  const handleClear = useCallback(async () => {
    try {
      await fetch('/api/execution/clear', { method: 'POST' });
      setEvents([]);
    } catch {
      /* ignore */
    }
  }, []);

  const handleExport = useCallback(async () => {
    try {
      const res = await fetch('/api/execution/export?format=json');
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `execution_events_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {
      /* ignore */
    }
  }, []);

  const dockPositions: { key: DockPosition; label: string; icon: string }[] = [
    { key: 'right', label: 'Right', icon: '◧' },
    { key: 'bottom', label: 'Bottom', icon: '◢' },
    { key: 'left', label: 'Left', icon: '◨' },
    { key: 'window', label: 'Window', icon: '⬜' },
  ];

  // If compact (docked mode), render a smaller version
  if (compact) {
    return renderDockedView({
      events,
      handleClear,
      handleExport,
      setSelectedEvent,
      onClose,
      isConnected,
    });
  }

  // Full page view - 3 column layout
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '260px 1fr 280px',
        gap: '20px',
        height: 'calc(100vh - 120px)',
      }}
    >
      {/* LEFT COLUMN: Workflow Navigation */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', overflow: 'auto' }}>
        {/* Connection status */}
        <div
          style={{
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '12px',
            padding: '16px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <StatusIndicator status={isConnected ? 'online' : 'offline'} size="md" />
            <span
              style={{
                fontSize: '13px',
                fontWeight: '600',
                color: isConnected ? '#00ff88' : '#ff4444',
              }}
            >
              {isConnected ? 'Live Connected' : 'Disconnected'}
            </span>
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '8px',
              fontSize: '11px',
              color: '#888',
            }}
          >
            <div
              style={{
                background: 'rgba(0,0,0,0.2)',
                padding: '8px',
                borderRadius: '6px',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '18px', fontWeight: '700', color: '#00d4ff' }}>
                {status?.active_count || 0}
              </div>
              <div style={{ fontSize: '9px', color: '#666', marginTop: '2px' }}>ACTIVE</div>
            </div>
            <div
              style={{
                background: 'rgba(0,0,0,0.2)',
                padding: '8px',
                borderRadius: '6px',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '18px', fontWeight: '700', color: '#00ff88' }}>
                {status?.completed_count || 0}
              </div>
              <div style={{ fontSize: '9px', color: '#666', marginTop: '2px' }}>COMPLETED</div>
            </div>
            <div
              style={{
                background: 'rgba(0,0,0,0.2)',
                padding: '8px',
                borderRadius: '6px',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '18px', fontWeight: '700', color: '#ff4444' }}>
                {status?.failed_count || 0}
              </div>
              <div style={{ fontSize: '9px', color: '#666', marginTop: '2px' }}>FAILED</div>
            </div>
            <div
              style={{
                background: 'rgba(0,0,0,0.2)',
                padding: '8px',
                borderRadius: '6px',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '18px', fontWeight: '700', color: '#888' }}>
                {status?.total_events || 0}
              </div>
              <div style={{ fontSize: '9px', color: '#666', marginTop: '2px' }}>TOTAL</div>
            </div>
          </div>
        </div>

        {/* Active Tasks */}
        <div
          style={{
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '12px',
            padding: '16px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h4
            style={{
              fontSize: '12px',
              fontWeight: '600',
              color: '#888',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              marginBottom: '12px',
            }}
          >
            ⚡ Active Tasks
          </h4>
          {(status?.active || []).length === 0 ? (
            <div
              style={{ fontSize: '11px', color: '#555', textAlign: 'center', padding: '16px 0' }}
            >
              No active tasks
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {status?.active.slice(0, 10).map((event) => (
                <div
                  key={event.id}
                  onClick={() => setSelectedEvent(event)}
                  style={{
                    padding: '8px 10px',
                    background: 'rgba(0,212,255,0.05)',
                    borderRadius: '6px',
                    borderLeft: '2px solid #00d4ff',
                    cursor: 'pointer',
                    fontSize: '11px',
                  }}
                >
                  <div style={{ color: '#ccc', marginBottom: '2px' }}>{event.message}</div>
                  <div style={{ display: 'flex', gap: '8px', fontSize: '9px', color: '#666' }}>
                    <span>{event.timestamp}</span>
                    <span>{event.source}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Failures */}
        {(status?.latest_failed || []).length > 0 && (
          <div
            style={{
              background: 'rgba(255,68,68,0.06)',
              borderRadius: '12px',
              padding: '14px',
              border: '1px solid rgba(255,68,68,0.15)',
            }}
          >
            <h4
              style={{
                fontSize: '12px',
                fontWeight: '600',
                color: '#ff4444',
                marginBottom: '10px',
              }}
            >
              ❌ Recent Failures
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {status?.latest_failed.map((f) => (
                <div
                  key={f.id}
                  style={{
                    fontSize: '11px',
                    color: '#ff6666',
                    padding: '6px 8px',
                    background: 'rgba(0,0,0,0.2)',
                    borderRadius: '4px',
                  }}
                >
                  {f.message}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Task type breakdown */}
        {systemStatus && (
          <div
            style={{
              background: 'rgba(15,15,26,0.95)',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
            }}
          >
            <h4
              style={{
                fontSize: '12px',
                fontWeight: '600',
                color: '#888',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '10px',
              }}
            >
              📊 Event Breakdown
            </h4>
            {Object.entries(systemStatus.event_type_breakdown).map(([type, count]) => (
              <div
                key={type}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '6px',
                  fontSize: '11px',
                }}
              >
                <span style={{ color: '#888' }}>{type}</span>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    flex: 1,
                    marginLeft: '8px',
                  }}
                >
                  <div
                    style={{
                      flex: 1,
                      height: '4px',
                      background: 'rgba(255,255,255,0.05)',
                      borderRadius: '2px',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${(count / Math.max(...Object.values(systemStatus.event_type_breakdown))) * 100}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #00d4ff, #00ff88)',
                        borderRadius: '2px',
                        transition: 'width 0.3s',
                      }}
                    />
                  </div>
                  <span
                    style={{
                      color: '#aaa',
                      fontWeight: '600',
                      minWidth: '20px',
                      textAlign: 'right',
                    }}
                  >
                    {count}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CENTER COLUMN: Live Execution Stream */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', overflow: 'hidden' }}>
        {/* Tabs */}
        <div
          style={{
            display: 'flex',
            gap: '8px',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            paddingBottom: '12px',
          }}
        >
          {[
            { id: 'stream' as MonitorTab, label: '📡 Live Stream', desc: 'Real-time event feed' },
            { id: 'pipeline' as MonitorTab, label: '🚀 Pipeline', desc: 'Bug Bounty stages' },
            { id: 'status' as MonitorTab, label: '📊 Status', desc: 'System health' },
            { id: 'history' as MonitorTab, label: '📜 History', desc: 'Searchable logs' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '10px 16px',
                borderRadius: '8px',
                border: 'none',
                background: activeTab === tab.id ? 'rgba(0,212,255,0.12)' : 'transparent',
                color: activeTab === tab.id ? '#00d4ff' : '#888',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: activeTab === tab.id ? '600' : '400',
                transition: 'all 0.2s',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'stream' && (
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <LiveLogStream
              events={events}
              maxHeight="100%"
              onClear={handleClear}
              onExport={handleExport}
              onEventClick={setSelectedEvent}
            />
          </div>
        )}

        {activeTab === 'pipeline' && (
          <div style={{ flex: 1, overflow: 'auto' }}>
            <PipelineTracker
              stages={pipelineStages}
              findingsCount={42}
              totalDuration="--:--:--"
              onStageClick={(id) => {
                setSelectedEvent(events.find((e) => e.id === String(id)) || null);
              }}
            />
          </div>
        )}

        {activeTab === 'status' && (
          <div style={{ flex: 1, overflow: 'auto' }}>
            <SystemStatusPanel status={systemStatus} events={events} />
          </div>
        )}

        {activeTab === 'history' && (
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <HistoryPanel events={events} />
          </div>
        )}
      </div>

      {/* RIGHT COLUMN: System Status & Event Details */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', overflow: 'auto' }}>
        {/* Project context */}
        <div
          style={{
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '12px',
            padding: '16px',
            border: '1px solid rgba(255,255,255,0.05)',
          }}
        >
          <h4
            style={{
              fontSize: '12px',
              fontWeight: '600',
              color: '#888',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              marginBottom: '12px',
            }}
          >
            🎯 Current Session
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '11px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#666' }}>Project</span>
              <span style={{ color: '#00d4ff', fontWeight: '600' }}>
                {projectId ? projectId.slice(0, 12) + '...' : 'Global'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#666' }}>Events</span>
              <span style={{ color: '#fff', fontWeight: '600' }}>{events.length}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#666' }}>Source Count</span>
              <span style={{ color: '#fff', fontWeight: '600' }}>
                {systemStatus ? Object.keys(systemStatus.source_breakdown).length : 0}
              </span>
            </div>
          </div>
        </div>

        {/* Event Details */}
        {selectedEvent ? (
          <EventDetailCard event={selectedEvent} onClose={() => setSelectedEvent(null)} />
        ) : (
          <div
            style={{
              flex: 1,
              background: 'rgba(15,15,26,0.95)',
              borderRadius: '12px',
              padding: '20px',
              border: '1px solid rgba(255,255,255,0.05)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#666',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔍</div>
            <div
              style={{ fontSize: '13px', fontWeight: '600', color: '#888', marginBottom: '4px' }}
            >
              Select an Event
            </div>
            <div style={{ fontSize: '11px' }}>
              Click any event in the stream to inspect its full details
            </div>
          </div>
        )}

        {/* Dock controls */}
        {onDockChange && (
          <div
            style={{
              background: 'rgba(15,15,26,0.95)',
              borderRadius: '12px',
              padding: '14px',
              border: '1px solid rgba(255,255,255,0.05)',
            }}
          >
            <h4
              style={{
                fontSize: '11px',
                fontWeight: '600',
                color: '#888',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                marginBottom: '10px',
              }}
            >
              📌 Dock Position
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '6px' }}>
              {dockPositions.map((dp) => (
                <button
                  key={dp.key}
                  onClick={() => onDockChange(dp.key)}
                  style={{
                    padding: '8px 4px',
                    borderRadius: '6px',
                    border:
                      dockPosition === dp.key
                        ? '1px solid #00d4ff'
                        : '1px solid rgba(255,255,255,0.08)',
                    background: dockPosition === dp.key ? 'rgba(0,212,255,0.1)' : 'rgba(0,0,0,0.2)',
                    color: dockPosition === dp.key ? '#00d4ff' : '#888',
                    cursor: 'pointer',
                    fontSize: '10px',
                    fontWeight: '600',
                    textAlign: 'center',
                    transition: 'all 0.15s',
                  }}
                >
                  <div style={{ fontSize: '14px', marginBottom: '2px' }}>{dp.icon}</div>
                  {dp.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============ DOCKED VIEW (compact) ============

function renderDockedView({
  events,
  handleClear,
  handleExport,
  setSelectedEvent,
  onClose,
  isConnected,
}: {
  events: LogEvent[];
  handleClear: () => void;
  handleExport: () => void;
  setSelectedEvent: (e: LogEvent | null) => void;
  onClose?: () => void;
  isConnected: boolean;
}) {
  return (
    <div
      style={{
        background: 'rgba(10,10,15,0.98)',
        borderTop: '1px solid rgba(255,255,255,0.08)',
        height: '250px',
        display: 'flex',
        flexDirection: 'column',
        backdropFilter: 'blur(10px)',
      }}
    >
      {/* Toolbar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: '13px', fontWeight: '600', color: '#888' }}>📡 Monitor</span>
        <StatusIndicator status={isConnected ? 'online' : 'offline'} size="sm" />
        <div style={{ flex: 1 }} />
        <button onClick={handleClear} style={dockBtnStyle}>
          🗑️
        </button>
        <button onClick={handleExport} style={dockBtnStyle}>
          📥
        </button>
        {onClose && (
          <button onClick={onClose} style={dockBtnStyle}>
            ✕
          </button>
        )}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflow: 'hidden' }}>
        <LiveLogStream events={events} maxHeight="100%" compact onEventClick={setSelectedEvent} />
      </div>
    </div>
  );
}

const dockBtnStyle: React.CSSProperties = {
  padding: '4px 8px',
  borderRadius: '4px',
  border: 'none',
  background: 'rgba(255,255,255,0.05)',
  color: '#888',
  cursor: 'pointer',
  fontSize: '11px',
};

// ============ EVENT DETAIL CARD ============

function EventDetailCard({ event, onClose }: { event: LogEvent; onClose: () => void }) {
  const severityColors: Record<string, string> = {
    info: '#888',
    success: '#00ff88',
    warning: '#ffaa00',
    error: '#ff4444',
    debug: '#aa88ff',
  };
  return (
    <div
      style={{
        background: 'rgba(15,15,26,0.95)',
        borderRadius: '12px',
        padding: '16px',
        border: '1px solid rgba(255,255,255,0.05)',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '14px',
        }}
      >
        <h4
          style={{
            fontSize: '12px',
            fontWeight: '600',
            color: '#888',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
          }}
        >
          📋 Event Details
        </h4>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: '#888',
            cursor: 'pointer',
            fontSize: '14px',
          }}
        >
          ✕
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '11px' }}>
        <div
          style={{
            padding: '10px',
            background: `${severityColors[event.severity] || '#888'}10`,
            borderRadius: '8px',
            borderLeft: `3px solid ${severityColors[event.severity] || '#888'}`,
          }}
        >
          <div style={{ fontWeight: '600', color: '#fff', marginBottom: '4px' }}>
            {event.message}
          </div>
          {event.details && <div style={{ color: '#888', fontSize: '10px' }}>{event.details}</div>}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
          <InfoRow label="Timestamp" value={event.timestamp} />
          <InfoRow label="Type" value={event.type} />
          <InfoRow label="Status" value={event.status} />
          <InfoRow label="Severity" value={event.severity} color={severityColors[event.severity]} />
          <InfoRow label="Source" value={event.source} />
          <InfoRow label="Category" value={event.category || '—'} />
        </div>

        {event.toolName && <InfoRow label="Tool" value={event.toolName} />}
        {event.duration_ms !== undefined && (
          <InfoRow label="Duration" value={`${event.duration_ms}ms`} />
        )}
        {event.details && <InfoRow label="Full Details" value={event.details} />}
      </div>
    </div>
  );
}

function InfoRow({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ padding: '6px 8px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px' }}>
      <div
        style={{ color: '#666', fontSize: '9px', marginBottom: '2px', textTransform: 'uppercase' }}
      >
        {label}
      </div>
      <div
        style={{
          color: color || '#ccc',
          fontWeight: '500',
          fontSize: '11px',
          wordBreak: 'break-all',
        }}
      >
        {value}
      </div>
    </div>
  );
}

// ============ SYSTEM STATUS PANEL ============

function SystemStatusPanel({
  status,
  events,
}: {
  status: SystemStatus | null;
  events: LogEvent[];
}) {
  const running = events.filter((e) => e.status === 'running' || e.status === 'processing');
  const bySource: Record<string, number> = {};
  events.forEach((e) => {
    bySource[e.source] = (bySource[e.source] || 0) + 1;
  });
  const topSources = Object.entries(bySource)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Health Card */}
      <div
        style={{
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          padding: '20px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <h3 style={{ fontSize: '15px', fontWeight: '600', marginBottom: '16px' }}>
          📊 System Health
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
          <StatusMetric label="Active Tasks" value={status?.active_tasks || 0} color="#00d4ff" />
          <StatusMetric label="Total Events" value={events.length} color="#888" />
          <StatusMetric label="Running Now" value={running.length} color="#00ff88" />
        </div>
        {status?.active_descriptions && status.active_descriptions.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div
              style={{
                fontSize: '10px',
                color: '#666',
                textTransform: 'uppercase',
                marginBottom: '6px',
              }}
            >
              Currently Active
            </div>
            {status.active_descriptions.map((desc, i) => (
              <div
                key={i}
                style={{
                  fontSize: '11px',
                  color: '#00d4ff',
                  padding: '4px 0',
                  borderBottom: '1px solid rgba(255,255,255,0.03)',
                }}
              >
                ▶ {desc}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Source Breakdown */}
      <div
        style={{
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          padding: '20px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <h3 style={{ fontSize: '15px', fontWeight: '600', marginBottom: '16px' }}>
          🔗 Source Activity
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {topSources.map(([source, count]) => {
            const maxCount = topSources[0]?.[1] || 1;
            return (
              <div key={source} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '11px', color: '#888', minWidth: '80px' }}>{source}</span>
                <div
                  style={{
                    flex: 1,
                    height: '6px',
                    background: 'rgba(255,255,255,0.05)',
                    borderRadius: '3px',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      width: `${(count / maxCount) * 100}%`,
                      height: '100%',
                      background: 'linear-gradient(90deg, #00d4ff, #00ff88)',
                      borderRadius: '3px',
                      transition: 'width 0.3s',
                    }}
                  />
                </div>
                <span
                  style={{
                    fontSize: '11px',
                    color: '#aaa',
                    fontWeight: '600',
                    minWidth: '24px',
                    textAlign: 'right',
                  }}
                >
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent errors */}
      {status?.recent_errors && status.recent_errors.length > 0 && (
        <div
          style={{
            background: 'rgba(255,68,68,0.06)',
            borderRadius: '16px',
            padding: '20px',
            border: '1px solid rgba(255,68,68,0.15)',
          }}
        >
          <h3
            style={{ fontSize: '15px', fontWeight: '600', color: '#ff4444', marginBottom: '12px' }}
          >
            ❌ Recent Errors ({status.recent_errors.length})
          </h3>
          {status.recent_errors.map((err) => (
            <div
              key={err.id}
              style={{
                padding: '10px',
                marginBottom: '8px',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px',
                borderLeft: '3px solid #ff4444',
              }}
            >
              <div style={{ fontSize: '12px', color: '#ff6666', fontWeight: '600' }}>
                {err.message}
              </div>
              <div style={{ fontSize: '10px', color: '#888', marginTop: '4px' }}>
                {err.timestamp} • {err.source} • {err.type}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusMetric({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div
      style={{
        textAlign: 'center',
        padding: '14px',
        background: 'rgba(0,0,0,0.2)',
        borderRadius: '10px',
      }}
    >
      <div style={{ fontSize: '24px', fontWeight: '700', color }}>{value}</div>
      <div
        style={{ fontSize: '10px', color: '#666', marginTop: '4px', textTransform: 'uppercase' }}
      >
        {label}
      </div>
    </div>
  );
}

// ============ HISTORY PANEL ============

function HistoryPanel({ events }: { events: LogEvent[] }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const uniqueTypes = [...new Set(events.map((e) => e.type))];
  const uniqueSeverities = [...new Set(events.map((e) => e.severity))];

  const filtered = events.filter((e) => {
    if (severityFilter !== 'all' && e.severity !== severityFilter) {
      return false;
    }
    if (typeFilter !== 'all' && e.type !== typeFilter) {
      return false;
    }
    if (searchQuery && !e.message.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    return true;
  });

  // Group by time (per minute)
  const groups: Record<string, LogEvent[]> = {};
  filtered.forEach((e) => {
    const key = e.timestamp ? e.timestamp.split(':').slice(0, 2).join(':') : 'unknown';
    if (!groups[key]) {
      groups[key] = [];
    }
    groups[key].push(e);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Search bar */}
      <div
        style={{
          display: 'flex',
          gap: '8px',
          marginBottom: '12px',
          flexWrap: 'wrap',
        }}
      >
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="🔍 Search execution history..."
          style={{
            flex: 1,
            minWidth: '150px',
            padding: '8px 12px',
            background: 'rgba(0,0,0,0.3)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: '8px',
            color: '#fff',
            fontSize: '12px',
            outline: 'none',
          }}
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={filterStyle}
        >
          <option value="all">All Types</option>
          {uniqueTypes.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={filterStyle}
        >
          <option value="all">All Severities</option>
          {uniqueSeverities.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {/* Results */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        {Object.keys(groups).length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
            <div style={{ fontSize: '28px', marginBottom: '8px' }}>🔍</div>
            <div style={{ fontSize: '13px', color: '#888' }}>No matching events</div>
          </div>
        ) : (
          Object.entries(groups)
            .reverse()
            .map(([time, evts]) => (
              <div key={time} style={{ marginBottom: '16px' }}>
                <div
                  style={{
                    fontSize: '10px',
                    color: '#555',
                    fontWeight: '600',
                    marginBottom: '8px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px',
                  }}
                >
                  {time} — {evts.length} events
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {evts.reverse().map((evt) => (
                    <div
                      key={evt.id}
                      style={{
                        padding: '8px 12px',
                        background: 'rgba(0,0,0,0.15)',
                        borderRadius: '6px',
                        borderLeft: `3px solid ${
                          evt.severity === 'error'
                            ? '#ff4444'
                            : evt.severity === 'warning'
                              ? '#ffaa00'
                              : evt.severity === 'success'
                                ? '#00ff88'
                                : '#888'
                        }`,
                        fontSize: '11px',
                      }}
                    >
                      <div style={{ color: '#ccc' }}>{evt.message}</div>
                      <div
                        style={{
                          fontSize: '9px',
                          color: '#666',
                          marginTop: '2px',
                          display: 'flex',
                          gap: '8px',
                        }}
                      >
                        <span>{evt.timestamp}</span>
                        <span>{evt.source}</span>
                        <span>{evt.type}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))
        )}
      </div>
    </div>
  );
}

const filterStyle: React.CSSProperties = {
  padding: '8px 10px',
  background: 'rgba(0,0,0,0.3)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '8px',
  color: '#888',
  fontSize: '11px',
  cursor: 'pointer',
  outline: 'none',
};
