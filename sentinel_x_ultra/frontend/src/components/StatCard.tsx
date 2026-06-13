export function StatCard({
  label,
  value,
  icon,
  color,
  trend,
}: {
  label: string;
  value: string;
  icon: string;
  color: string;
  trend?: string;
}) {
  return (
    <div
      style={{
        background: 'rgba(15, 15, 26, 0.95)',
        borderRadius: '10px',
        padding: '14px',
        border: `1px solid ${color}30`,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          top: '-14px',
          right: '-14px',
          width: '50px',
          height: '50px',
          background: `${color}15`,
          borderRadius: '50%',
        }}
      />
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '8px',
        }}
      >
        <div style={{ fontSize: '22px' }}>{icon}</div>
        {trend && (
          <span
            style={{
              background: trend.startsWith('+') ? '#00ff8830' : '#ff444430',
              color: trend.startsWith('+') ? '#00ff88' : '#ff4444',
              fontSize: '10px',
              fontWeight: '600',
              padding: '2px 6px',
              borderRadius: '3px',
            }}
          >
            {trend}
          </span>
        )}
      </div>
      <div style={{ fontSize: '24px', fontWeight: 'bold', color, marginBottom: '3px' }}>
        {value}
      </div>
      <div style={{ fontSize: '11px', color: '#666' }}>{label}</div>
    </div>
  );
}
