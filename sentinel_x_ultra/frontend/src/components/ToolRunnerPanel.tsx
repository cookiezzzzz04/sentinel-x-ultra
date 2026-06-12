import { useState, useEffect } from 'react'
import { ToolRunnerService } from '../services/ToolRunnerService'
import type { ToolRun, ToolDefinition, ToolLogEntry } from '../services/ToolRunnerService'
import { StatusIndicator, ProgressBar } from './StatusIndicator'

export function ToolRunnerPanel() {
  const [tools, setTools] = useState<ToolDefinition[]>([])
  const [runs, setRuns] = useState<ToolRun[]>([])
  const [selectedTool, setSelectedTool] = useState<string | null>(null)
  const [params, setParams] = useState<Record<string, any>>({})
  const [showNewRun, setShowNewRun] = useState(false)
  const [expandedRun, setExpandedRun] = useState<string | null>(null)

  useEffect(() => {
    ToolRunnerService.getAvailableTools().then(setTools)
    const unsub = ToolRunnerService.subscribe(() => {
      setRuns([...ToolRunnerService.getRuns()])
    })
    return () => { unsub() }
  }, [])

  const handleStart = async () => {
    if (!selectedTool) return
    const tool = tools.find(t => t.name === selectedTool)
    if (!tool) return
    // Validate required params
    for (const p of tool.params) {
      if (p.required && !params[p.name]) {
        return
      }
    }
    await ToolRunnerService.startTool(selectedTool, { ...params, target: params.target || 'example.com' })
    setShowNewRun(false)
    setParams({})
  }

  const tool = tools.find(t => t.name === selectedTool)

  const stateColors: Record<string, string> = {
    queued: '#888',
    starting: '#00d4ff',
    running: '#00d4ff',
    completed: '#00ff88',
    failed: '#ff4444',
    cancelled: '#888',
  }

  const toolCategoryIcons: Record<string, string> = {
    recon: '🎯',
    scanning: '🔍',
    fuzzing: '⚡',
    exploit: '💥',
    utility: '🔧',
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Left Panel */}
      <div>
        {/* Header */}
        <div style={{
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          padding: '20px',
          border: '1px solid rgba(255,255,255,0.05)',
          marginBottom: '16px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
              🔧 Tool Runner
            </h3>
            <button
              onClick={() => { setShowNewRun(true); setSelectedTool(tools[0]?.name || null) }}
              style={{
                padding: '8px 16px',
                borderRadius: '8px',
                border: 'none',
                background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
                color: '#000',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: '700',
              }}
            >
              + New Run
            </button>
          </div>

          {/* Available tools grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
            {tools.map(t => (
              <div key={t.name} style={{
                padding: '12px',
                background: t.installed ? 'rgba(0,255,136,0.05)' : 'rgba(255,68,68,0.05)',
                borderRadius: '8px',
                border: `1px solid ${t.installed ? 'rgba(0,255,136,0.15)' : 'rgba(255,68,68,0.15)'}`,
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '20px', marginBottom: '4px' }}>{toolCategoryIcons[t.category] || '🔧'}</div>
                <div style={{ fontSize: '11px', fontWeight: '600', color: t.installed ? '#00ff88' : '#ff4444' }}>{t.displayName}</div>
                <div style={{ fontSize: '9px', color: '#666', marginTop: '2px' }}>
                  {t.installed ? `v${t.version}` : 'Not installed'}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* New Run Form */}
        {showNewRun && (
          <div style={{
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '16px',
            padding: '20px',
            border: '1px solid rgba(0,212,255,0.2)',
            marginBottom: '16px',
            animation: 'fadeInUp 0.2s ease',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#00d4ff' }}>New Tool Run</h4>
              <button onClick={() => setShowNewRun(false)} style={{
                background: 'none', border: 'none', color: '#888', cursor: 'pointer', fontSize: '16px',
              }}>✕</button>
            </div>

            {/* Tool selection */}
            <select
              value={selectedTool || ''}
              onChange={(e) => { setSelectedTool(e.target.value); setParams({}) }}
              style={{
                width: '100%',
                padding: '10px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                color: '#fff',
                fontSize: '13px',
                marginBottom: '16px',
              }}
            >
              {tools.map(t => (
                <option key={t.name} value={t.name} disabled={!t.installed}>
                  {t.displayName} {!t.installed ? '(not installed)' : ''}
                </option>
              ))}
            </select>

            {/* Tool params */}
            {tool && tool.params.map(p => (
              <div key={p.name} style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#888', marginBottom: '4px' }}>
                  {p.label} {p.required && <span style={{ color: '#ff4444' }}>*</span>}
                </label>
                {p.type === 'select' ? (
                  <select
                    value={params[p.name] || p.defaultValue || ''}
                    onChange={(e) => setParams({ ...params, [p.name]: e.target.value })}
                    style={{
                      width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)',
                      border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff', fontSize: '13px',
                    }}
                  >
                    {(p.options || []).map(o => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={params[p.name] || ''}
                    onChange={(e) => setParams({ ...params, [p.name]: e.target.value })}
                    placeholder={p.placeholder}
                    style={{
                      width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)',
                      border: `1px solid ${p.required && !params[p.name] ? 'rgba(255,68,68,0.3)' : 'rgba(255,255,255,0.1)'}`,
                      borderRadius: '8px', color: '#fff', fontSize: '13px',
                    }}
                  />
                )}
              </div>
            ))}

            <button
              onClick={handleStart}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: 'none',
                background: 'linear-gradient(135deg, #00d4ff, #00ff88)',
                color: '#000',
                cursor: 'pointer',
                fontSize: '13px',
                fontWeight: '700',
              }}
            >
              ▶ Run {tool?.displayName || 'Tool'}
            </button>
          </div>
        )}

        {/* Run History */}
        <div style={{
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          border: '1px solid rgba(255,255,255,0.05)',
          overflow: 'hidden',
        }}>
          <div style={{ padding: '16px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4 style={{ fontSize: '13px', fontWeight: '600', color: '#888' }}>Run History</h4>
            {runs.length > 0 && (
              <button onClick={() => ToolRunnerService.clearAll()} style={{
                padding: '4px 10px',
                background: 'rgba(255,68,68,0.1)',
                border: 'none',
                borderRadius: '4px',
                color: '#ff4444',
                cursor: 'pointer',
                fontSize: '10px',
              }}>
                Clear All
              </button>
            )}
          </div>

          {runs.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: '#666' }}>
              <div style={{ fontSize: '24px', marginBottom: '8px' }}>🔧</div>
              <div style={{ fontSize: '13px' }}>No tool runs yet</div>
            </div>
          ) : (
            <div>
              {runs.map(run => (
                <div key={run.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                  <div
                    onClick={() => setExpandedRun(expandedRun === run.id ? null : run.id)}
                    style={{
                      padding: '12px 16px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      transition: 'background 0.15s',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.02)' }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
                  >
                    <div style={{ fontSize: '16px' }}>{toolCategoryIcons[tools.find(t => t.name === run.toolName)?.category || 'utility']}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '13px', fontWeight: '600' }}>{run.toolName}</div>
                      <div style={{ fontSize: '11px', color: '#666' }}>
                        {new Date(run.startTime).toLocaleTimeString()} • {run.duration || '—'}
                      </div>
                    </div>
                    <StatusIndicator status={run.state} size="sm" />
                    <div style={{ display: 'flex', gap: '4px' }}>
                      {(run.state === 'running' || run.state === 'queued') && (
                        <button
                          onClick={(e) => { e.stopPropagation(); ToolRunnerService.cancelRun(run.id) }}
                          style={{ padding: '4px 8px', background: 'rgba(255,68,68,0.15)', border: 'none', borderRadius: '4px', color: '#ff4444', cursor: 'pointer', fontSize: '10px' }}
                        >
                          Stop
                        </button>
                      )}
                      {(run.state === 'completed' || run.state === 'failed' || run.state === 'cancelled') && (
                        <button
                          onClick={(e) => { e.stopPropagation(); ToolRunnerService.restartRun(run.id) }}
                          style={{ padding: '4px 8px', background: 'rgba(0,212,255,0.15)', border: 'none', borderRadius: '4px', color: '#00d4ff', cursor: 'pointer', fontSize: '10px' }}
                        >
                          ↻
                        </button>
                      )}
                      <button
                        onClick={(e) => { e.stopPropagation(); ToolRunnerService.clearRun(run.id) }}
                        style={{ padding: '4px 8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '4px', color: '#666', cursor: 'pointer', fontSize: '10px' }}
                      >
                        ✕
                      </button>
                    </div>
                  </div>

                  {/* Expanded details */}
                  {expandedRun === run.id && (
                    <div style={{ padding: '0 16px 16px', animation: 'fadeIn 0.15s ease' }}>
                      {run.currentTask && (
                        <div style={{ marginBottom: '8px', fontSize: '12px', color: '#00d4ff' }}>
                          Current: {run.currentTask}
                        </div>
                      )}
                      {run.progress && (
                        <div style={{ marginBottom: '8px' }}>
                          <ProgressBar value={run.progress.current} max={run.progress.total} color="#00d4ff" height={3} />
                          <div style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>
                            {run.progress.current} / {run.progress.total}
                          </div>
                        </div>
                      )}
                      {run.summary && (
                        <div style={{ marginBottom: '8px', fontSize: '12px', color: '#888' }}>
                          {run.summary}
                        </div>
                      )}
                      {run.errors && run.errors.length > 0 && (
                        <div style={{ marginBottom: '8px', padding: '8px', background: 'rgba(255,68,68,0.1)', borderRadius: '6px', fontSize: '11px', color: '#ff4444' }}>
                          {run.errors.join(', ')}
                        </div>
                      )}
                      {/* Logs */}
                      <div style={{
                        maxHeight: '200px',
                        overflow: 'auto',
                        background: 'rgba(0,0,0,0.3)',
                        borderRadius: '8px',
                        padding: '10px',
                        fontFamily: 'monospace',
                        fontSize: '11px',
                      }}>
                        {run.logs.map((log, i) => (
                          <div key={i} style={{
                            color: log.level === 'error' ? '#ff4444' : log.level === 'warn' ? '#ffaa00' : log.level === 'result' ? '#00ff88' : '#aaa',
                            marginBottom: '2px',
                          }}>
                            [{new Date(log.timestamp).toLocaleTimeString()}] {log.message}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right: Tool activity in context */}
      <div style={{
        background: 'rgba(15,15,26,0.95)',
        borderRadius: '16px',
        border: '1px solid rgba(255,255,255,0.05)',
        padding: '24px',
      }}>
        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          📋 Tool Activity
        </h3>
        {runs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 20px', color: '#666' }}>
            <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔧</div>
            <div style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px', color: '#888' }}>No tool activity yet</div>
            <div style={{ fontSize: '12px' }}>Start a tool run and its output will appear here</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {runs.slice(0, 5).map(run => (
              <div key={run.id} style={{
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px',
                borderLeft: `3px solid ${stateColors[run.state] || '#888'}`,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '13px', fontWeight: '600' }}>{run.toolName}</span>
                  <StatusIndicator status={run.state} size="sm" />
                </div>
                <div style={{ fontSize: '11px', color: '#666' }}>
                  {new Date(run.startTime).toLocaleTimeString()} • {run.duration || 'Running...'}
                </div>
                {run.targetsFound !== undefined && (
                  <div style={{ fontSize: '11px', color: '#00ff88', marginTop: '4px' }}>
                    Found: {run.targetsFound} targets
                  </div>
                )}
                {/* Latest log line preview */}
                {run.logs.length > 0 && (
                  <div style={{
                    marginTop: '6px',
                    fontSize: '10px',
                    color: '#555',
                    fontFamily: 'monospace',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}>
                    {run.logs[run.logs.length - 1].message}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
