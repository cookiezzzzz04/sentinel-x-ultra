import { useState, useEffect } from 'react';

export function FindingsPanel({ projectId }: { projectId: string }) {
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('All');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const res = await fetch(`/api/projects/${projectId}/findings`);
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) setFindings(data.findings || []);
        }
      } catch (e) {
        /* keep empty */
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  const filtered =
    filter === 'All'
      ? findings
      : findings.filter((f) => f.severity?.toUpperCase() === filter.toUpperCase());

  const severityColors: Record<string, string> = {
    CRITICAL: '#ff4444',
    HIGH: '#ff8844',
    MEDIUM: '#ffaa00',
    LOW: '#00d4ff',
    INFO: '#888',
  };

  return (
    <div>
      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
          marginBottom: '24px',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '16px',
          }}
        >
          <h3 style={{ fontSize: '16px', fontWeight: '600' }}>Filters</h3>
          {findings.length > 0 && (
            <span style={{ fontSize: '12px', color: '#888' }}>
              {findings.length} unique finding{findings.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                background: filter === f ? 'rgba(0, 212, 255, 0.1)' : 'rgba(255,255,255,0.05)',
                border: `1px solid ${filter === f ? '#00d4ff' : 'rgba(255,255,255,0.1)'}`,
                color: filter === f ? '#00d4ff' : '#888',
                padding: '8px 16px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '12px',
                transition: 'all 0.2s',
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ padding: '48px', textAlign: 'center', color: '#666' }}>
          <div
            style={{
              width: '32px',
              height: '32px',
              border: '3px solid rgba(0,212,255,0.15)',
              borderTopColor: '#00d4ff',
              borderRadius: '50%',
              animation: 'spin 0.8s linear infinite',
              margin: '0 auto 16px',
            }}
          />
          <div style={{ fontSize: '13px' }}>Loading findings...</div>
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ padding: '48px', textAlign: 'center', color: '#666' }}>
          <div style={{ fontSize: '40px', marginBottom: '12px' }}>🔍</div>
          <div style={{ fontWeight: '600', marginBottom: '4px', color: '#888', fontSize: '15px' }}>
            No findings yet
          </div>
          <div style={{ fontSize: '13px' }}>
            Run agents or the Bug Bounty pipeline to generate findings.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filtered.map((finding, idx) => (
            <div
              key={finding.id || idx}
              style={{
                background: 'rgba(15, 15, 26, 0.95)',
                borderRadius: '12px',
                padding: '20px',
                border: `1px solid ${severityColors[finding.severity] || '#888'}30`,
                borderLeft: `4px solid ${severityColors[finding.severity] || '#888'}`,
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = severityColors[finding.severity] || '#888';
                e.currentTarget.style.transform = 'translateX(4px)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = `${severityColors[finding.severity] || '#888'}30`;
                e.currentTarget.style.transform = 'translateX(0)';
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  marginBottom: '8px',
                }}
              >
                <h4 style={{ fontSize: '15px', fontWeight: '600' }}>{finding.title}</h4>
                <span
                  style={{
                    background: `${severityColors[finding.severity] || '#888'}20`,
                    color: severityColors[finding.severity] || '#888',
                    fontSize: '11px',
                    fontWeight: '600',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    textTransform: 'uppercase',
                  }}
                >
                  {finding.severity}
                </span>
              </div>
              <p style={{ fontSize: '13px', color: '#888', marginBottom: '12px' }}>
                {finding.description}
              </p>
              <div
                style={{
                  display: 'flex',
                  gap: '16px',
                  fontSize: '12px',
                  color: '#666',
                  flexWrap: 'wrap',
                }}
              >
                {finding.target && <span>📍 {finding.target}</span>}
                {finding.cvss && <span>📊 CVSS: {finding.cvss}</span>}
                {finding.source && <span>🔗 Source: {finding.source}</span>}
                {finding.references && finding.references.length > 0 && (
                  <span>📋 {finding.references.join(', ')}</span>
                )}
              </div>
              {finding.steps_to_reproduce && finding.steps_to_reproduce.length > 0 && (
                <div
                  style={{
                    marginTop: '12px',
                    padding: '12px',
                    background: 'rgba(0,0,0,0.2)',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#aaa',
                  }}
                >
                  <div
                    style={{
                      fontWeight: '600',
                      marginBottom: '8px',
                      color: '#00d4ff',
                      fontSize: '11px',
                      textTransform: 'uppercase',
                    }}
                  >
                    Steps to Reproduce
                  </div>
                  {finding.steps_to_reproduce.map((step: any, i: number) => (
                    <div
                      key={i}
                      style={{
                        marginBottom: '4px',
                        paddingLeft: '8px',
                        borderLeft: '2px solid rgba(0,212,255,0.3)',
                      }}
                    >
                      {i + 1}.{' '}
                      {typeof step === 'string'
                        ? step
                        : step.action || step.description || JSON.stringify(step)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
