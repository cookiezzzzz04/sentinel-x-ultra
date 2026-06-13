import { useState, useEffect, useRef } from 'react';

export function AIReportPanel({ projectId }: { projectId: string }) {
  const [report, setReport] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [view, setView] = useState<'executive' | 'technical' | 'full'>('full');
  const [stats, setStats] = useState<any>(null);
  const userGenerated = useRef(false);

  useEffect(() => {
    fetch(`/api/projects/${projectId}/analysis-summary`)
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});

    // Load any saved bug bounty pipeline report (only if user hasn't generated a report)
    fetch(`/api/projects/${projectId}/bug-bounty-report`)
      .then((r) => r.json())
      .then((data) => {
        if (data.has_report && data.report_text && !userGenerated.current) {
          setReport(data.report_text);
        }
      })
      .catch(() => {});
  }, [projectId]);

  const generate = async () => {
    userGenerated.current = true;
    setLoading(true);
    setError('');
    setReport('');
    try {
      const res = await fetch(`/api/projects/${projectId}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ view }),
      });
      const data = await res.json();
      if (data.status === 'error') {
        setError(data.error || 'Report failed');
        return;
      }
      setReport(data.report_markdown || '');
    } catch (e: any) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const download = () => {
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-x-report-${projectId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(170,136,255,0.1), rgba(0,212,255,0.05))',
          borderRadius: '12px',
          padding: '20px',
          border: '1px solid rgba(170,136,255,0.2)',
          marginBottom: '20px',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div>
            <h2 style={{ fontSize: '22px', fontWeight: 'bold', marginBottom: '4px' }}>
              <span
                style={{
                  background: 'linear-gradient(90deg, #aa88ff, #00d4ff)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                }}
              >
                📝 AI Report
              </span>
            </h2>
            <p style={{ fontSize: '13px', color: '#888' }}>
              The configured model writes a Blank.md report from the findings.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <select
              value={view}
              onChange={(e) => setView(e.target.value as any)}
              style={{
                padding: '8px 12px',
                background: '#0a0a0a',
                color: '#fff',
                border: '1px solid #333',
                borderRadius: '6px',
                fontSize: '12px',
              }}
            >
              <option value="executive">Executive</option>
              <option value="technical">Technical</option>
              <option value="full">Full</option>
            </select>
            <button
              onClick={generate}
              disabled={loading}
              style={{
                padding: '8px 20px',
                background: loading
                  ? 'rgba(255,255,255,0.1)'
                  : 'linear-gradient(135deg, #aa88ff, #00d4ff)',
                color: loading ? '#666' : '#fff',
                border: 'none',
                borderRadius: '6px',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontSize: '12px',
                fontWeight: '700',
              }}
            >
              {loading ? '⏳ Writing...' : '✨ Generate'}
            </button>
            {report && (
              <button
                onClick={download}
                style={{
                  padding: '8px 16px',
                  background: 'rgba(0,255,136,0.1)',
                  color: '#00ff88',
                  border: '1px solid rgba(0,255,136,0.3)',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '12px',
                  fontWeight: '600',
                }}
              >
                ⬇ Download .md
              </button>
            )}
          </div>
        </div>
        {stats && (
          <div
            style={{
              display: 'flex',
              gap: '16px',
              marginTop: '12px',
              fontSize: '12px',
              color: '#888',
            }}
          >
            <span>🎯 {stats.code_analysis?.patterns_found || 0} code patterns</span>
            <span>🌐 {stats.web_analysis?.vulnerabilities || 0} web vulns</span>
            <span>🛡️ {stats.knowledge_graph?.attack_paths || 0} attack paths</span>
          </div>
        )}
        {error && (
          <div
            style={{
              marginTop: '12px',
              padding: '8px 12px',
              background: 'rgba(255,68,68,0.1)',
              color: '#ff4444',
              borderRadius: '6px',
              fontSize: '12px',
            }}
          >
            ⚠️ {error}
          </div>
        )}
      </div>
      <div
        style={{
          background: 'rgba(10,10,15,0.95)',
          border: '1px solid rgba(255,255,255,0.05)',
          borderRadius: '12px',
          padding: '20px',
          minHeight: '400px',
        }}
      >
        {report ? (
          <pre
            style={{
              whiteSpace: 'pre-wrap',
              fontFamily: 'ui-monospace, SFMono-Regular, monospace',
              fontSize: '13px',
              color: '#e0e0e0',
              lineHeight: '1.6',
              margin: 0,
            }}
          >
            {report}
          </pre>
        ) : (
          <div style={{ textAlign: 'center', padding: '80px 20px', color: '#666' }}>
            <div style={{ fontSize: '48px', marginBottom: '12px' }}>📝</div>
            <div style={{ fontSize: '14px', marginBottom: '8px', color: '#888' }}>
              No report yet
            </div>
            <div style={{ fontSize: '12px' }}>
              Click <span style={{ color: '#aa88ff', fontWeight: '600' }}>Generate</span> to have
              the model draft a report.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
