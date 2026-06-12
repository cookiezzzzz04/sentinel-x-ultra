import { useState } from 'react'
import { StatusIndicator, ProgressBar } from './StatusIndicator'
import type { StatusType } from './StatusIndicator'

export interface PipelineStage {
  id: number
  name: string
  description: string
  status: 'waiting' | 'running' | 'completed' | 'failed' | 'skipped'
  icon: string
  progress?: { current: number; total: number }
  startedAt?: string
  completedAt?: string
  findings?: number
}

interface PipelineTrackerProps {
  stages: PipelineStage[]
  currentStageId?: number | null
  findingsCount?: number
  totalDuration?: string
  onStageClick?: (stageId: number) => void
}

const stageStatusConfig: Record<string, { color: string; label: string }> = {
  waiting: { color: '#555', label: 'Waiting' },
  running: { color: '#00d4ff', label: 'Running' },
  completed: { color: '#00ff88', label: 'Complete' },
  failed: { color: '#ff4444', label: 'Failed' },
  skipped: { color: '#666', label: 'Skipped' },
}

export function PipelineTracker({ stages, currentStageId, findingsCount, totalDuration, onStageClick }: PipelineTrackerProps) {
  const [expanded, setExpanded] = useState<number | null>(null)
  const activeIdx = stages.findIndex(s => s.status === 'running')
  const completedCount = stages.filter(s => s.status === 'completed').length

  return (
    <div style={{
      background: 'rgba(15,15,26,0.95)',
      borderRadius: '16px',
      padding: '20px',
      border: '1px solid rgba(255,255,255,0.05)',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3 style={{ fontSize: '16px', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
            🚀 Bug Bounty Pipeline
          </h3>
          <p style={{ fontSize: '12px', color: '#666', marginTop: '2px' }}>
            {completedCount}/{stages.length} stages complete
            {findingsCount !== undefined && ` • ${findingsCount} findings`}
            {totalDuration && ` • ${totalDuration}`}
          </p>
        </div>
        {activeIdx >= 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{
              width: '8px', height: '8px', borderRadius: '50%',
              background: '#00d4ff', animation: 'pulse 1s infinite',
              boxShadow: '0 0 8px rgba(0,212,255,0.6)',
            }} />
            <span style={{ fontSize: '12px', color: '#00d4ff', fontWeight: '600' }}>
              Stage {activeIdx + 1}: {stages[activeIdx]?.name}
            </span>
          </div>
        )}
      </div>

      {/* Pipeline visual - horizontal stages */}
      <div style={{ position: 'relative', marginBottom: '24px' }}>
        {/* Connection line */}
        <div style={{
          position: 'absolute',
          top: '20px',
          left: '30px',
          right: '30px',
          height: '2px',
          background: 'rgba(255,255,255,0.06)',
          zIndex: 0,
        }}>
          {/* Active progress overlay */}
          {activeIdx > 0 && (
            <div style={{
              position: 'absolute',
              left: 0,
              top: 0,
              height: '100%',
              width: `${(activeIdx / Math.max(stages.length - 1, 1)) * 100}%`,
              background: 'linear-gradient(90deg, #00d4ff, #00ff88)',
              transition: 'width 0.5s ease',
            }} />
          )}
        </div>

        {/* Stage circles */}
        <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', zIndex: 1 }}>
          {stages.map((stage, _idx) => {
            const cfg = stageStatusConfig[stage.status]
            const isCurrent = stage.status === 'running' || stage.id === currentStageId
            const isPast = stage.status === 'completed'
            const isFailed = stage.status === 'failed'

            return (
              <div
                key={stage.id}
                onClick={() => onStageClick?.(stage.id)}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '8px',
                  cursor: onStageClick ? 'pointer' : 'default',
                  flex: 1,
                  opacity: stage.status === 'waiting' ? 0.4 : 1,
                  transition: 'all 0.3s ease',
                }}
              >
                {/* Circle */}
                <div style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '16px',
                  background: isPast
                    ? 'linear-gradient(135deg, #00ff88, #00d4ff)'
                    : isCurrent
                    ? 'rgba(0,212,255,0.15)'
                    : isFailed
                    ? 'rgba(255,68,68,0.15)'
                    : 'rgba(255,255,255,0.05)',
                  border: isCurrent
                    ? '2px solid #00d4ff'
                    : isPast
                    ? '2px solid #00ff88'
                    : isFailed
                    ? '2px solid #ff4444'
                    : '2px solid rgba(255,255,255,0.1)',
                  boxShadow: isCurrent ? '0 0 16px rgba(0,212,255,0.3)' : 'none',
                  transition: 'all 0.3s ease',
                  animation: isCurrent ? 'pulse 2s infinite' : 'none',
                }}>
                  {isPast ? '✓' : isFailed ? '✕' : stage.icon}
                </div>

                {/* Label */}
                <div style={{ textAlign: 'center', maxWidth: '80px' }}>
                  <div style={{
                    fontSize: '10px',
                    fontWeight: '600',
                    color: isPast ? '#00ff88' : isCurrent ? '#00d4ff' : isFailed ? '#ff4444' : '#888',
                    marginBottom: '2px',
                    lineHeight: 1.2,
                  }}>
                    {stage.name}
                  </div>
                  <div style={{
                    fontSize: '8px',
                    color: cfg.color,
                    textTransform: 'uppercase',
                    letterSpacing: '0.3px',
                  }}>
                    {cfg.label}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Stage details - expandable */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {stages.map((stage) => {
          const isExpanded = expanded === stage.id
          return (
            <div
              key={stage.id}
              onClick={() => setExpanded(isExpanded ? null : stage.id)}
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                background: stage.status === 'running'
                  ? 'rgba(0,212,255,0.06)'
                  : stage.status === 'failed'
                  ? 'rgba(255,68,68,0.06)'
                  : 'rgba(0,0,0,0.15)',
                border: `1px solid ${
                  stage.status === 'running' ? 'rgba(0,212,255,0.2)' :
                  stage.status === 'failed' ? 'rgba(255,68,68,0.2)' :
                  'rgba(255,255,255,0.03)'
                }`,
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '16px' }}>{stage.icon}</span>
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: '600', color: '#ccc' }}>
                      Stage {stage.id}: {stage.name}
                    </div>
                    <div style={{ fontSize: '10px', color: '#666' }}>{stage.description}</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <StatusIndicator status={stage.status as StatusType} size="sm" />
                  {stage.findings !== undefined && stage.findings > 0 && (
                    <span style={{
                      background: 'rgba(0,255,136,0.1)',
                      color: '#00ff88',
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontWeight: '600',
                    }}>
                      {stage.findings} findings
                    </span>
                  )}
                  <span style={{ fontSize: '10px', color: '#555' }}>
                    {isExpanded ? '▲' : '▼'}
                  </span>
                </div>
              </div>

              {/* Expanded content */}
              {isExpanded && (
                <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                  {stage.progress && (
                    <div style={{ marginBottom: '8px' }}>
                      <ProgressBar value={stage.progress.current} max={stage.progress.total} color="#00d4ff" height={4} showLabel />
                    </div>
                  )}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px', color: '#888' }}>
                    {stage.startedAt && <div>Started: {stage.startedAt}</div>}
                    {stage.completedAt && <div>Completed: {stage.completedAt}</div>}
                    {stage.findings !== undefined && <div>Findings: {stage.findings}</div>}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
