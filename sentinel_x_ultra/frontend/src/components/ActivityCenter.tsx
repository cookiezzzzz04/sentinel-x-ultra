import { useState, useEffect, useRef } from 'react'
import { StatusIndicator, ProgressBar } from './StatusIndicator'
import type { StatusType } from './StatusIndicator'

export interface ActivityEvent {
  id: string
  timestamp: string
  type: 'file_read' | 'analysis' | 'tool' | 'agent' | 'scan' | 'report' | 'proxy' | 'recon' | 'system'
  message: string
  details?: string
  status: StatusType
  progress?: { current: number; total: number }
  icon?: string
  filePath?: string
  functionsFound?: string[]
  toolName?: string
  duration?: string
}

interface ActivityCenterProps {
  events: ActivityEvent[]
  isOpen: boolean
  onToggle: () => void
  currentlyReading?: string
  functionsFound?: string[]
  filesProcessed?: { current: number; total: number }
}

const typeIcons: Record<string, string> = {
  file_read: '📄',
  analysis: '🔍',
  tool: '🔧',
  agent: '🤖',
  scan: '🚀',
  report: '📝',
  proxy: '🌐',
  recon: '🎯',
  system: '⚙️',
}

export function ActivityCenter({ events, isOpen, onToggle, currentlyReading, functionsFound, filesProcessed }: ActivityCenterProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [activeFilter, setActiveFilter] = useState<string>('all')

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [events.length])

  const filteredEvents = activeFilter === 'all'
    ? events
    : events.filter(e => e.type === activeFilter)

  const eventCounts = {
    all: events.length,
    file_read: events.filter(e => e.type === 'file_read').length,
    analysis: events.filter(e => e.type === 'analysis').length,
    tool: events.filter(e => e.type === 'tool').length,
    agent: events.filter(e => e.type === 'agent').length,
    scan: events.filter(e => e.type === 'scan').length,
    proxy: events.filter(e => e.type === 'proxy').length,
    recon: events.filter(e => e.type === 'recon').length,
  }

  return (
    <>
      {/* Toggle button */}
      <button
        onClick={onToggle}
        style={{
          position: 'fixed',
          right: isOpen ? '420px' : '20px',
          top: '80px',
          zIndex: 200,
          width: '44px',
          height: '44px',
          borderRadius: '12px',
          border: '1px solid rgba(255,255,255,0.1)',
          background: isOpen ? '#00d4ff' : 'rgba(15,15,26,0.95)',
          color: isOpen ? '#000' : '#888',
          cursor: 'pointer',
          fontSize: '18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'all 0.3s ease',
          boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
        }}
      >
        {isOpen ? '✕' : '📋'}
        {events.filter(e => e.status === 'running' || e.status === 'processing').length > 0 && (
          <span style={{
            position: 'absolute',
            top: '-4px',
            right: '-4px',
            width: '12px',
            height: '12px',
            borderRadius: '50%',
            background: '#00d4ff',
            animation: 'pulse 1s infinite',
          }} />
        )}
      </button>

      {/* Panel */}
      <div style={{
        position: 'fixed',
        right: isOpen ? 0 : '-420px',
        top: 0,
        width: '400px',
        height: '100vh',
        background: 'rgba(10, 10, 15, 0.97)',
        borderLeft: '1px solid rgba(255,255,255,0.05)',
        zIndex: 150,
        display: 'flex',
        flexDirection: 'column',
        transition: 'right 0.3s ease',
        backdropFilter: 'blur(20px)',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
              📋 Activity Center
              <span style={{ fontSize: '11px', color: '#666', fontWeight: '400' }}>
                {events.length} event{events.length !== 1 ? 's' : ''}
              </span>
            </h3>
          </div>

          {/* File visibility */}
          {currentlyReading && (
            <div style={{
              padding: '12px',
              background: 'rgba(0,212,255,0.08)',
              borderRadius: '8px',
              border: '1px solid rgba(0,212,255,0.15)',
              marginBottom: '12px',
            }}>
              <div style={{ fontSize: '11px', color: '#00d4ff', fontWeight: '600', marginBottom: '6px' }}>
                📖 Currently Reading
              </div>
              <div style={{ fontSize: '13px', fontFamily: 'monospace', color: '#fff', marginBottom: '4px' }}>
                {currentlyReading}
              </div>
              {functionsFound && functionsFound.length > 0 && (
                <div style={{ marginTop: '6px' }}>
                  <div style={{ fontSize: '10px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    Functions Found:
                  </div>
                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
                    {functionsFound.map((fn, i) => (
                      <span key={i} style={{
                        fontSize: '10px',
                        background: 'rgba(0,255,136,0.1)',
                        color: '#00ff88',
                        padding: '2px 6px',
                        borderRadius: '3px',
                        fontFamily: 'monospace',
                      }}>
                        {fn}()
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {filesProcessed && (
                <div style={{ marginTop: '8px' }}>
                  <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>
                    Files Processed: {filesProcessed.current} / {filesProcessed.total}
                  </div>
                  <ProgressBar value={filesProcessed.current} max={filesProcessed.total} color="#00d4ff" height={3} />
                </div>
              )}
            </div>
          )}

          {/* Filter chips */}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {Object.entries(eventCounts).map(([key, count]) => (
              <button
                key={key}
                onClick={() => setActiveFilter(key)}
                style={{
                  padding: '4px 10px',
                  borderRadius: '6px',
                  border: 'none',
                  background: activeFilter === key ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.05)',
                  color: activeFilter === key ? '#00d4ff' : '#666',
                  cursor: 'pointer',
                  fontSize: '10px',
                  fontWeight: '600',
                  transition: 'all 0.2s',
                }}
              >
                {key === 'all' ? 'All' : typeIcons[key] || key} {count}
              </button>
            ))}
          </div>
        </div>

        {/* Event timeline */}
        <div
          ref={scrollRef}
          style={{
            flex: 1,
            overflow: 'auto',
            padding: '12px',
          }}
        >
          {filteredEvents.length === 0 ? (
            <div style={{
              textAlign: 'center',
              padding: '48px 20px',
              color: '#666',
            }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>📋</div>
              <div style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px', color: '#888' }}>No activity yet</div>
              <div style={{ fontSize: '12px' }}>Run a scan or agent to see live activity here</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {filteredEvents.map((event) => {
                const time = new Date(event.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

                return (
                  <div
                    key={event.id}
                    style={{
                      padding: '10px 12px',
                      borderRadius: '8px',
                      background: event.status === 'running' || event.status === 'processing'
                        ? 'rgba(0,212,255,0.05)'
                        : 'transparent',
                      border: event.status === 'running'
                        ? '1px solid rgba(0,212,255,0.1)'
                        : '1px solid transparent',
                      animation: 'fadeIn 0.2s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                      <span style={{ fontSize: '14px', flexShrink: 0, marginTop: '1px' }}>
                        {event.icon || typeIcons[event.type] || '•'}
                      </span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: '12px', color: '#ccc', lineHeight: '1.4' }}>
                          {event.message}
                        </div>
                        {event.details && (
                          <div style={{ fontSize: '11px', color: '#666', marginTop: '2px' }}>
                            {event.details}
                          </div>
                        )}
                        {event.progress && (
                          <div style={{ marginTop: '6px' }}>
                            <ProgressBar
                              value={event.progress.current}
                              max={event.progress.total}
                              color="#00d4ff"
                              height={3}
                            />
                          </div>
                        )}
                        <div style={{ display: 'flex', gap: '8px', marginTop: '4px', alignItems: 'center' }}>
                          <span style={{ fontSize: '10px', color: '#555', fontFamily: 'monospace' }}>{time}</span>
                          <StatusIndicator status={event.status} size="sm" />
                          {event.toolName && (
                            <span style={{ fontSize: '10px', color: '#666' }}>{event.toolName}</span>
                          )}
                          {event.duration && (
                            <span style={{ fontSize: '10px', color: '#666' }}>⏱ {event.duration}</span>
                          )}
                        </div>
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
          padding: '12px 20px',
          borderTop: '1px solid rgba(255,255,255,0.05)',
          fontSize: '10px',
          color: '#555',
          textAlign: 'center',
          flexShrink: 0,
        }}>
          {events.filter(e => e.status === 'running').length} active • Last: {events.length > 0 ? new Date(events[events.length - 1].timestamp).toLocaleTimeString() : 'N/A'}
        </div>
      </div>
    </>
  )
}

// WebSocket hook for live activity
export function useActivityStream(projectId?: string) {
  const [events, setEvents] = useState<ActivityEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!projectId) return
    let ws: WebSocket | null = null
    let reconnectTimer: ReturnType<typeof setTimeout>

    const connect = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const host = window.location.host
        ws = new WebSocket(`${protocol}//${host}/api/ws/activity?project_id=${projectId}`)
        wsRef.current = ws

        ws.onopen = () => setIsConnected(true)
        ws.onclose = () => {
          setIsConnected(false)
          reconnectTimer = setTimeout(connect, 3000)
        }
        ws.onerror = () => ws?.close()
        ws.onmessage = (msg) => {
          try {
            const event = JSON.parse(msg.data) as ActivityEvent
            setEvents(prev => [...prev.slice(-199), event]) // Keep last 200
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
    }

    connect()
    return () => {
      clearTimeout(reconnectTimer)
      ws?.close()
      wsRef.current = null
    }
  }, [projectId])

  const addEvent = (event: Omit<ActivityEvent, 'id' | 'timestamp'>) => {
    const newEvent: ActivityEvent = {
      ...event,
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      timestamp: new Date().toISOString(),
    }
    setEvents(prev => [...prev.slice(-199), newEvent])
    return newEvent
  }

  return { events, setEvents, addEvent, isConnected }
}
