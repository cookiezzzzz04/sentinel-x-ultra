import { useState } from 'react';

interface ButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'gradient';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  loading?: boolean;
  fullWidth?: boolean;
  icon?: string;
  type?: 'button' | 'submit';
  style?: React.CSSProperties;
}

const variantStyles: Record<
  string,
  { bg: string; color: string; border: string; hoverBg: string; hoverBorder: string }
> = {
  primary: {
    bg: 'rgba(0, 212, 255, 0.1)',
    color: '#00d4ff',
    border: '1px solid rgba(0, 212, 255, 0.3)',
    hoverBg: 'rgba(0, 212, 255, 0.2)',
    hoverBorder: '1px solid #00d4ff',
  },
  secondary: {
    bg: 'rgba(255, 255, 255, 0.05)',
    color: '#888',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    hoverBg: 'rgba(255, 255, 255, 0.1)',
    hoverBorder: '1px solid rgba(255, 255, 255, 0.2)',
  },
  danger: {
    bg: 'rgba(255, 68, 68, 0.1)',
    color: '#ff4444',
    border: '1px solid rgba(255, 68, 68, 0.3)',
    hoverBg: 'rgba(255, 68, 68, 0.2)',
    hoverBorder: '1px solid #ff4444',
  },
  ghost: {
    bg: 'transparent',
    color: '#888',
    border: '1px solid transparent',
    hoverBg: 'rgba(255, 255, 255, 0.05)',
    hoverBorder: '1px solid transparent',
  },
  gradient: {
    bg: 'linear-gradient(135deg, #00d4ff, #00ff88)',
    color: '#000',
    border: 'none',
    hoverBg: 'linear-gradient(135deg, #00d4ff, #00ff88)',
    hoverBorder: 'none',
  },
};

const sizeStyles: Record<string, { padding: string; fontSize: string }> = {
  sm: { padding: '6px 12px', fontSize: '11px' },
  md: { padding: '10px 16px', fontSize: '13px' },
  lg: { padding: '14px 24px', fontSize: '14px' },
};

export function Button({
  children,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  fullWidth = false,
  icon,
  type = 'button',
  style,
}: ButtonProps) {
  const [isHovered, setIsHovered] = useState(false);
  const vs = variantStyles[variant];
  const ss = sizeStyles[size];

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        padding: ss.padding,
        fontSize: ss.fontSize,
        fontWeight: '600',
        borderRadius: '8px',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'all 0.2s ease',
        whiteSpace: 'nowrap',
        width: fullWidth ? '100%' : 'auto',
        background: isHovered && !disabled ? vs.hoverBg : vs.bg,
        color: vs.color,
        border: isHovered && !disabled ? vs.hoverBorder : vs.border,
        ...style,
      }}
    >
      {loading ? (
        <span
          style={{
            width: '14px',
            height: '14px',
            border: '2px solid rgba(255,255,255,0.2)',
            borderTopColor: '#fff',
            borderRadius: '50%',
            animation: 'spin 0.6s linear infinite',
          }}
        />
      ) : icon ? (
        <span style={{ fontSize: '14px' }}>{icon}</span>
      ) : null}
      {children}
    </button>
  );
}
