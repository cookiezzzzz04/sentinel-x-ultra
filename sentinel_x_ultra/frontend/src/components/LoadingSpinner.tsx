export function LoadingSpinner() {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '48px',
        color: '#666',
        fontSize: '14px',
        gap: '12px',
      }}
    >
      <div
        style={{
          width: '24px',
          height: '24px',
          border: '3px solid rgba(0, 212, 255, 0.15)',
          borderTopColor: '#00d4ff',
          borderRadius: '50%',
          animation: 'spin 0.8s linear infinite',
        }}
      />
      <span>Loading...</span>
    </div>
  );
}
