export function NavItem({
  icon,
  label,
  active,
  collapsed,
  onClick,
  badge,
}: {
  icon: string;
  label: string;
  active: boolean;
  collapsed: boolean;
  onClick: () => void;
  badge?: string;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: collapsed ? '12px' : '12px 16px',
        marginBottom: '4px',
        background: active
          ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.15), rgba(0, 255, 136, 0.1))'
          : 'transparent',
        border: active ? '1px solid rgba(0, 212, 255, 0.3)' : '1px solid transparent',
        borderRadius: '10px',
        color: active ? '#00d4ff' : '#888',
        cursor: 'pointer',
        transition: 'all 0.2s',
        justifyContent: collapsed ? 'center' : 'flex-start',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <span style={{ fontSize: '18px', flexShrink: 0 }}>{icon}</span>
      {!collapsed && (
        <>
          <span style={{ fontSize: '14px', fontWeight: active ? '600' : '400', flex: 1 }}>
            {label}
          </span>
          {badge && (
            <span
              style={{
                background: 'linear-gradient(135deg, #ff8844, #ff4488)',
                color: '#fff',
                fontSize: '9px',
                fontWeight: '700',
                padding: '2px 6px',
                borderRadius: '4px',
              }}
            >
              {badge}
            </span>
          )}
        </>
      )}
      {active && (
        <div
          style={{
            position: 'absolute',
            left: 0,
            top: '50%',
            transform: 'translateY(-50%)',
            width: '3px',
            height: '60%',
            background: 'linear-gradient(180deg, #00d4ff, #00ff88)',
            borderRadius: '0 2px 2px 0',
          }}
        />
      )}
    </button>
  );
}
