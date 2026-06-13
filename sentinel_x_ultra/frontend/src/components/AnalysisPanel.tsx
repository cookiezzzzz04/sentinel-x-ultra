import { useState } from 'react';

export function AnalysisPanel({ projectId }: { projectId: string }) {
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [codeInput, setCodeInput] = useState(
    '// Paste vulnerable code here\nconst query = "SELECT * FROM users WHERE id = " + userId;',
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const runCodeAnalysis = async () => {
    setIsAnalyzing(true);
    try {
      const res = await fetch(`/api/projects/${projectId}/analyze/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: codeInput, file_path: 'example.js', language: 'javascript' }),
      });
      const data = await res.json();
      setAnalysisResult(data);
    } catch (e) {
      console.error('Analysis failed:', e);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div>
      <h3 style={{ fontSize: '18px', marginBottom: '16px' }}>🔍 Code Analysis (SAST)</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div>
          <textarea
            value={codeInput}
            onChange={(e) => setCodeInput(e.target.value)}
            style={{
              width: '100%',
              minHeight: '350px',
              background: 'rgba(10, 10, 15, 0.95)',
              border: '1px solid rgba(255,255,255,0.05)',
              borderRadius: '12px',
              padding: '16px',
              color: '#00d4ff',
              fontFamily: 'monospace',
              fontSize: '13px',
              resize: 'vertical',
              outline: 'none',
            }}
            placeholder="Paste code to analyze..."
          />
          <button
            onClick={runCodeAnalysis}
            disabled={isAnalyzing}
            style={{
              marginTop: '16px',
              width: '100%',
              background: isAnalyzing
                ? 'rgba(255,255,255,0.1)'
                : 'linear-gradient(135deg, #00d4ff, #00ff88)',
              color: isAnalyzing ? '#666' : '#000',
              border: 'none',
              borderRadius: '10px',
              padding: '14px',
              fontWeight: '700',
              cursor: isAnalyzing ? 'not-allowed' : 'pointer',
              fontSize: '14px',
            }}
          >
            {isAnalyzing ? '⏳ Analyzing...' : '▶ Analyze Code'}
          </button>
        </div>
        <div
          style={{
            background: 'rgba(15, 15, 26, 0.95)',
            borderRadius: '12px',
            padding: '20px',
            border: '1px solid rgba(255,255,255,0.05)',
            minHeight: '350px',
          }}
        >
          <h4 style={{ fontSize: '14px', marginBottom: '16px', color: '#888' }}>
            Analysis Results
          </h4>
          {analysisResult ? (
            <div style={{ fontFamily: 'monospace', fontSize: '12px' }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, 1fr)',
                  gap: '12px',
                  marginBottom: '16px',
                }}
              >
                <div
                  style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}
                >
                  <div style={{ color: '#666', marginBottom: '4px' }}>Patterns Found</div>
                  <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#00d4ff' }}>
                    {analysisResult.summary?.patterns_found || 0}
                  </div>
                </div>
                <div
                  style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}
                >
                  <div style={{ color: '#666', marginBottom: '4px' }}>Critical Issues</div>
                  <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff4444' }}>
                    {analysisResult.summary?.critical || 0}
                  </div>
                </div>
              </div>
              {analysisResult.patterns?.length > 0 && (
                <div style={{ marginTop: '16px' }}>
                  <div style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>
                    Vulnerabilities:
                  </div>
                  {analysisResult.patterns.map((p: any, i: number) => (
                    <div
                      key={i}
                      style={{
                        background: 'rgba(0,0,0,0.3)',
                        padding: '12px',
                        borderRadius: '8px',
                        marginBottom: '8px',
                        borderLeft: `3px solid ${p.severity === 'CRITICAL' ? '#ff4444' : p.severity === 'HIGH' ? '#ff8844' : p.severity === 'MEDIUM' ? '#ffaa00' : '#888'}`,
                      }}
                    >
                      <div style={{ fontWeight: '600', color: '#fff', marginBottom: '4px' }}>
                        {p.name}
                      </div>
                      <div style={{ fontSize: '11px', color: '#666' }}>{p.description}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div
              style={{ color: '#666', fontSize: '13px', textAlign: 'center', paddingTop: '100px' }}
            >
              Run analysis to see results
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
