import { useState, useRef, useEffect } from 'react'
import { StatusIndicator, ProgressBar } from './StatusIndicator'
import type { StatusType } from './StatusIndicator'

export interface LogEvent {
  id: string
  timestamp: string
  type: string
  message: string
  status: string
  severity: 'info' | 'success' | 'warning' | 'error' | 'debug'
  source: string
  category?: string
  details?: string
  icon?: string
  toolName?: string
  progress?: { current: number; total: number }
  duration_ms?: number
}

interface LiveLogStreamProps {
  events: LogEvent[]
  maxHeight?: string
  compact?: boolean
  filters?: {
    types?: string[]
    severities?: string[]
    sources?: string[]
  }
  onEventClick?: (event: LogEvent) => void
  onClear?: () => void
  onExport?: () => void
  title?: string
}

const severityConfig = {
  info: { color: '#888', bg: 'transparent', label: 'INFO', icon: 'ℹ️' },
  success: { color: '#00ff88', bg: 'rgba(0,255,136,0.08)', label: 'SUCCESS', icon: '✅' },
  warning: { color: '#ffaa00', bg: 'rgba(255,170,0,0.08)', label: 'WARNING', icon: '⚠️' },
  error: { color: '#ff4444', bg: 'rgba(255,68,68,0.08)', label: 'ERROR', icon: '❌' },
  debug: { color: '#aa88ff', bg: 'rgba(170,136,255,0.08)', label: 'DEBUG', icon: '🔍' },
}

const sourceIcons: Record<string, string> = {
  agent: '🤖',
  scan: '🚀',
  analysis: '🔍',
  tool: '🔧',
  proxy: '🌐',
  recon: '🎯',
  system: '⚙️',
  file_read: '📄',
  report: '📝',
  bug_bounty: '🏴',
}

export function LiveLogStream({
  events,
  maxHeight = '500px',
  compact = false,
  filters: _filters,
  onEventClick,
  onClear,
  onExport,
  title = 'Live Execution Stream',
}: LiveLogStreamProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [events.length, autoScroll])

  const handleScroll = () => {
    if (!scrollRef.current) return
    const el = scrollRef.current
    const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50
    setAutoScroll(isAtBottom)
  }

  const filteredEvents = events.filter(e => {
    if (typeFilter !== 'all' && e.type !== typeFilter) return false
    if (severityFilter !== 'all' && e.severity !== severityFilter) return false
    if (searchQuery && !e.message.toLowerCase().includes(searchQuery.toLowerCase())
      && !(e.details || '').toLowerCase().includes(searchQuery.toLowerCase())) return false
    return true
  })

  const uniqueTypes = [...new Set(events.map(e => e.type))]
  const uniqueSeverities = [...new Set(events.map(e => e.severity))]

  const eventCounts = {
    all: events.length,
    info: events.filter(e => e.severity === 'info').length,
    success: events.filter(e => e.severity === 'success').length,
    warning: events.filter(e => e.severity === 'warning').length,
    error: events.filter(e => e.severity === 'error').length,
  }

  return (
    <div style={{
      background: 'rgba(10,10,15,0.97)',
      borderRadius: '12px',
      border: '1px solid rgba(255,255,255,0.05)',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: compact ? '10px 14px' : '14px 18px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '8px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <h3 style={{ fontSize: compact ? '13px' : '15px', fontWeight: '600' }}>{title}</h3>
          <span style={{ fontSize: '11px', color: '#666' }}>{events.length} events</span>
          {events.filter(e => e.status === 'running').length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <div style={{
                width: '6px', height: '6px', borderRadius: '50%',
                background: '#00d4ff', animation: 'pulse 1s infinite',
              }} />
              <span style={{ fontSize: '10px', color: '#00d4ff' }}>LIVE</span>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          {onExport && (
            <button onClick={onExport} style={compactBtnStyle}>
              📥 Export
            </button>
          )}
          {onClear && (
            <button onClick={onClear} style={compactBtnStyle}>
              🗑️ Clear
            </button>
          )}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            style={{
              ...compactBtnStyle,
              background: autoScroll ? 'rgba(0,212,255,0.1)' : 'rgba(255,68,68,0.1)',
              color: autoScroll ? '#00d4ff' : '#ff4444',
            }}
          >
            {autoScroll ? '● Auto' : '■ Paused'}
          </button>
        </div>
      </div>

      {/* Filters bar */}
      {!compact && (
        <div style={{
          padding: '8px 14px',
          borderBottom: '1px solid rgba(255,255,255,0.03)',
          display: 'flex',
          gap: '8px',
          flexWrap: 'wrap',
          alignItems: 'center',
        }}>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="🔍 Search events..."
            style={{
              flex: 1,
              minWidth: '120px',
              padding: '6px 10px',
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '6px',
              color: '#fff',
              fontSize: '11px',
              outline: 'none',
            }}
          />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            style={filterSelectStyle}
          >
            <option value="all">All Types ({eventCounts.all})</option>
            {uniqueTypes.map(t => (
              <option key={t} value={t}>{sourceIcons[t] || '📋'} {t} ({events.filter(e => e.type === t).length})</option>
            ))}
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={filterSelectStyle}
          >
            <option value="all">All Severities</option>
            {uniqueSeverities.map(s => (
              <option key={s} value={s}>{severityConfig[s]?.icon || '•'} {s} ({events.filter(e => e.severity === s).length})</option>
            ))}
          </select>
        </div>
      )}

      {/* Event list */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        style={{
          flex: 1,
          overflow: 'auto',
          maxHeight,
          padding: compact ? '4px' : '8px',
        }}
      >
        {filteredEvents.length === 0 ? (
          <div style={{ padding: '40px 20px', textAlign: 'center', color: '#666' }}>
            <div style={{ fontSize: '28px', marginBottom: '8px' }}>📡</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: '#888', marginBottom: '4px' }}>
              No events to display
            </div>
            <div style={{ fontSize: '11px' }}>
              {searchQuery || typeFilter !== 'all' || severityFilter !== 'all'
                ? 'Try adjusting your filters'
                : 'Run a scan or agent to see live execution events'}
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: compact ? '1px' : '2px' }}>
            {filteredEvents.map((event) => {
              const sev = severityConfig[event.severity] || severityConfig.info
              const time = event.timestamp
              const isActive = event.status === 'running' || event.status === 'processing'

              return (
                <div
                  key={event.id}
                  onClick={() => onEventClick?.(event)}
                  style={{
                    padding: compact ? '6px 8px' : '8px 12px',
                    borderRadius: '6px',
                    background: isActive ? 'rgba(0,212,255,0.04)' : 'transparent',
                    borderLeft: `3px solid ${sev.color}`,
                    cursor: onEventClick ? 'pointer' : 'default',
                    transition: 'background 0.15s',
                    animation: 'fadeIn 0.15s ease',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.03)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = isActive ? 'rgba(0,212,255,0.04)' : 'transparent' }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                    {/* Icon */}
                    <span style={{ fontSize: compact ? '11px' : '13px', flexShrink: 0, marginTop: '1px' }}>
                      {event.icon || sourceIcons[event.type] || severityConfig[event.severity]?.icon || '•'}
                    </span>

                    {/* Content */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '10px', color: '#555', fontFamily: 'monospace' }}>{time}</span>
                        <span style={{
                          fontSize: '9px',
                          fontWeight: '700',
                          color: sev.color,
                          textTransform: 'uppercase',
                          letterSpacing: '0.3px',
                        }}>
                          {sev.label}
                        </span>
                        <span style={{ fontSize: '10px', color: '#888' }}>{event.source}</span>
                        {isActive && <StatusIndicator status="running" size="sm" showLabel={false} />}
                        {event.duration_ms && (
                          <span style={{ fontSize: '9px', color: '#666' }}>⏱ {event.duration_ms}ms</span>
                        )}
                      </div>
                      <div style={{
                        fontSize: compact ? '11px' : '12px',
                        color: event.severity === 'error' ? '#ff6666' : '#ccc',
                        marginTop: '2px',
                        lineHeight: 1.4,
                      }}>
                        {event.message}
                      </div>
                      {event.details && !compact && (
                        <div style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>
                          {event.details}
                        </div>
                      )}
                      {event.progress && !compact && (
                        <div style={{ marginTop: '4px', maxWidth: '300px' }}>
                          <ProgressBar value={event.progress.current} max={event.progress.total} color="#00d4ff" height={3} />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{
        padding: compact ? '6px 14px' : '8px 18px',
        borderTop: '1px solid rgba(255,255,255,0.03)',
        display: 'flex',
        justifyContent: 'space-between',
        fontSize: '10px',
        color: '#555',
        flexShrink: 0,
      }}>
        <span>{events.filter(e => e.status === 'running').length} active</span>
        <span>{events.length > 0 ? `Latest: ${events[events.length - 1].timestamp}` : '—'}</span>
      </div>
    </div>
  )
}

const compactBtnStyle: React.CSSProperties = {
  padding: '4px 10px',
  borderRadius: '5px',
  border: '1px solid rgba(255,255,255,0.08)',
  background: 'rgba(255,255,255,0.04)',
  color: '#888',
  cursor: 'pointer',
  fontSize: '10px',
  fontWeight: '600',
  transition: 'all 0.15s',
}

const filterSelectStyle: React.CSSProperties = {
  padding: '6px 10px',
  background: 'rgba(0,0,0,0.3)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '6px',
  color: '#888',
  fontSize: '11px',
  cursor: 'pointer',
  outline: 'none',
}
