export type StatusType = 'queued' | 'starting' | 'running' | 'reading' | 'processing' | 'waiting' | 'completed' | 'failed' | 'cancelled' | 'skipped' | 'idle' | 'online' | 'offline'

interface StatusIndicatorProps {
  status: StatusType
  label?: string
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  pulse?: boolean
}

const statusColors: Record<StatusType, string> = {
  queued: '#888',
  starting: '#00d4ff',
  running: '#00d4ff',
  reading: '#aa88ff',
  processing: '#ffaa00',
  waiting: '#ff8844',
  completed: '#00ff88',
  failed: '#ff4444',
  cancelled: '#888',
  skipped: '#555',
  idle: '#666',
  online: '#00ff88',
  offline: '#ff4444',
}

const statusLabels: Record<StatusType, string> = {
  queued: 'Queued',
  starting: 'Starting',
  running: 'Running',
  reading: 'Reading',
  processing: 'Processing',
  waiting: 'Waiting',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
  skipped: 'Skipped',
  idle: 'Idle',
  online: 'Online',
  offline: 'Offline',
}

const sizeMap: Record<string, { dot: number; fontSize: string }> = {
  sm: { dot: 6, fontSize: '10px' },
  md: { dot: 8, fontSize: '11px' },
  lg: { dot: 12, fontSize: '13px' },
}

export function StatusIndicator({ status, label, size = 'md', showLabel = true, pulse }: StatusIndicatorProps) {
  const s = sizeMap[size]
  const color = statusColors[status]
  const shouldPulse = pulse ?? (status === 'running' || status === 'processing' || status === 'starting')

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      fontSize: s.fontSize,
      fontWeight: '600',
      color,
    }}>
      <span style={{
        width: s.dot,
        height: s.dot,
        borderRadius: '50%',
        background: color,
        boxShadow: shouldPulse ? `0 0 6px ${color}` : 'none',
        animation: shouldPulse ? 'pulse 1.5s infinite' : 'none',
      }} />
      {showLabel && (label || statusLabels[status])}
    </span>
  )
}

export function ProgressBar({ value, max = 100, color = '#00d4ff', height = 4, showLabel = false }: {
  value: number
  max?: number
  color?: string
  height?: number
  showLabel?: boolean
}) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))
  return (
    <div>
      <div style={{
        width: '100%',
        height,
        background: 'rgba(255,255,255,0.05)',
        borderRadius: height / 2,
        overflow: 'hidden',
      }}>
        <div style={{
          width: `${pct}%`,
          height: '100%',
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          borderRadius: height / 2,
          transition: 'width 0.3s ease',
          animation: value < max ? 'progressPulse 1.5s infinite' : 'none',
        }} />
      </div>
      {showLabel && (
        <div style={{ fontSize: '11px', color: '#666', marginTop: '4px', textAlign: 'right' }}>
          {Math.round(pct)}%
        </div>
      )}
    </div>
  )
}

export function SkeletonLoader({ type = 'text', count = 1 }: { type?: 'text' | 'card' | 'avatar'; count?: number }) {
  const items = Array.from({ length: count })
  return (
    <>
      {items.map((_, i) => {
        const cls = `skeleton skeleton-${type}${type === 'text' ? (i % 3 === 0 ? ' short' : i % 3 === 1 ? ' tiny' : '') : ''}`
        const height = type === 'card' ? 120 : type === 'avatar' ? 40 : 14
        const width = type === 'text' ? (i % 3 === 0 ? '60%' : i % 3 === 1 ? '30%' : '100%') : '100%'
        return (
          <div
            key={i}
            className={cls}
            style={{
              height,
              width,
              marginBottom: type === 'text' ? 8 : 12,
              borderRadius: type === 'avatar' ? '50%' : 6,
              background: 'linear-gradient(90deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0.03) 100%)',
              backgroundSize: '200% 100%',
              animation: 'shimmer 1.5s infinite',
            }}
          />
        )
      })}
    </>
  )
}
