import { useEffect, useRef } from 'react'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  width?: string
}

export function Modal({ isOpen, onClose, title, children, width = '520px' }: ModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!isOpen) return
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleEsc)
    return () => document.removeEventListener('keydown', handleEsc)
  }, [isOpen, onClose])

  if (!isOpen) return null

  return (
    <div
      ref={overlayRef}
      onClick={(e) => { if (e.target === overlayRef.current) onClose() }}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0, 0, 0, 0.7)',
        backdropFilter: 'blur(4px)',
        animation: 'fadeIn 0.2s ease',
      }}
    >
      <div
        style={{
          width,
          maxWidth: '90vw',
          maxHeight: '85vh',
          background: 'rgba(15, 15, 26, 0.98)',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          boxShadow: '0 24px 80px rgba(0, 0, 0, 0.6)',
          animation: 'scaleIn 0.2s ease',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '20px 24px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          }}
        >
          <h3 style={{ fontSize: '18px', fontWeight: '600' }}>{title}</h3>
          <button
            onClick={onClose}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: 'none',
              color: '#888',
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.2s',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,68,68,0.2)'; e.currentTarget.style.color = '#ff4444' }}
            onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; e.currentTarget.style.color = '#888' }}
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: '24px', overflow: 'auto', flex: 1 }}>
          {children}
        </div>
      </div>
    </div>
  )
}

export function ConfirmDialog({ isOpen, onClose, onConfirm, title, message, confirmLabel = 'Confirm', confirmColor = '#ff4444' }: {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  message: string
  confirmLabel?: string
  confirmColor?: string
}) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title} width="400px">
      <p style={{ fontSize: '14px', color: '#888', marginBottom: '24px', lineHeight: '1.6' }}>{message}</p>
      <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
        <button
          onClick={onClose}
          style={{
            padding: '10px 20px',
            borderRadius: '8px',
            border: '1px solid rgba(255,255,255,0.1)',
            background: 'transparent',
            color: '#888',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: '600',
          }}
        >
          Cancel
        </button>
        <button
          onClick={() => { onConfirm(); onClose() }}
          style={{
            padding: '10px 20px',
            borderRadius: '8px',
            border: 'none',
            background: confirmColor,
            color: '#fff',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: '700',
          }}
        >
          {confirmLabel}
        </button>
      </div>
    </Modal>
  )
}
