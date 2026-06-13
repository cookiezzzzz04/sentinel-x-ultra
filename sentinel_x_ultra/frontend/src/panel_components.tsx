import React, { useState, useRef } from 'react';

const API_BASE = '/api';

// ============ INPUT SOURCES PANEL ============
export function InputSourcesPanel() {
  const [inputMethod, setInputMethod] = useState<'files' | 'webs' | 'code' | 'folder' | 'prompts'>(
    'files',
  );
  const [urls, setUrls] = useState<string[]>([]);
  const [urlInput, setUrlInput] = useState('');
  const [folderPath, setFolderPath] = useState('');
  const [codeInput, setCodeInput] = useState('');
  const [codeFilePath, setCodeFilePath] = useState('input_code.py');
  const [promptInput, setPromptInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Burp Suite state (Community Edition)
  const [burpFile, setBurpFile] = useState<File | null>(null);
  const [burpStatus, setBurpStatus] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addUrl = () => {
    if (urlInput.trim()) {
      setUrls([...urls, urlInput.trim()]);
      setUrlInput('');
    }
  };

  const analyzeUrls = async () => {
    if (urls.length === 0) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/input/urls`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error (${res.status}): ${text}`);
      }
      const data = await res.json();
      setResults({ type: 'urls', data });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const analyzeCode = async () => {
    if (!codeInput.trim()) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/input/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: codeInput,
          file_path: codeFilePath || 'input_code.py',
          language: codeFilePath?.split('.').pop() || 'py',
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error (${res.status}): ${text}`);
      }
      const data = await res.json();
      setResults({ type: 'code', data });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const scanFolder = async () => {
    if (!folderPath.trim()) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/input/folder`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder_path: folderPath }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error (${res.status}): ${text}`);
      }
      const data = await res.json();
      setResults({ type: 'folder', data });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const processPrompt = async () => {
    if (!promptInput.trim()) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/input/prompts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: promptInput }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error (${res.status}): ${text}`);
      }
      const data = await res.json();
      setResults({ type: 'prompt', data });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  // Burp Suite Community Edition file upload
  const handleBurpFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setBurpFile(file);
      setBurpStatus(null);
    }
  };

  const uploadBurpExport = async () => {
    if (!burpFile) {
      return;
    }
    setLoading(true);
    setError(null);
    setBurpStatus('Reading file...');

    try {
      // Read the JSON file
      const fileContent = await burpFile.text();
      const burpData = JSON.parse(fileContent);

      setBurpStatus('Analyzing requests...');

      const res = await fetch(`${API_BASE}/burp/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          burp_data: burpData,
          format: 'json',
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error (${res.status}): ${text}`);
      }
      const data = await res.json();

      if (data.status === 'ok') {
        setBurpStatus(`✓ Analyzed ${data.summary?.total_requests || 0} requests`);
        setResults({ type: 'burp', data });
      } else {
        setBurpStatus('✗ ' + (data.error || 'Upload failed'));
        setError(data.error || 'Upload failed');
      }
    } catch (e: any) {
      setBurpStatus('✗ Error: ' + e.message);
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const triggerFileSelect = () => {
    fileInputRef.current?.click();
  };

  const loadingOverlayContent = (() => {
    const text =
      inputMethod === 'webs'
        ? 'Analyzing URLs...'
        : inputMethod === 'code'
          ? 'Analyzing code...'
          : inputMethod === 'folder'
            ? 'Scanning folder...'
            : inputMethod === 'prompts'
              ? 'Processing prompt...'
              : 'Processing...';
    return (
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: 'rgba(10, 10, 15, 0.85)',
          borderRadius: '16px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '16px',
          zIndex: 10,
          backdropFilter: 'blur(4px)',
          animation: 'fadeIn 0.25s ease',
        }}
      >
        <div
          style={{
            width: '48px',
            height: '48px',
            border: '3px solid rgba(0, 212, 255, 0.15)',
            borderTopColor: '#00d4ff',
            borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
          }}
        />
        <div style={{ fontSize: '14px', fontWeight: '600', color: '#00d4ff' }}>{text}</div>
        <div style={{ fontSize: '12px', color: '#666' }}>
          AI-powered security analysis in progress
        </div>
      </div>
    );
  })();

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
          position: 'relative',
        }}
      >
        {loading && loadingOverlayContent}
        <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '8px', color: '#00d4ff' }}>
          📥 Input Sources
        </h3>
        <p style={{ fontSize: '13px', color: '#888', marginBottom: '20px' }}>
          Upload code files, scan URLs, analyze folders, or paste code directly for AI-powered
          security analysis
        </p>
        <div style={{ display: 'flex', gap: '8px', marginBottom: '24px', flexWrap: 'wrap' }}>
          {(['files', 'webs', 'code', 'folder', 'prompts'] as const).map((method) => (
            <button
              key={method}
              onClick={() => {
                setInputMethod(method);
                setResults(null);
                setError(null);
              }}
              style={{
                padding: '10px 16px',
                borderRadius: '8px',
                border: 'none',
                cursor: 'pointer',
                background: inputMethod === method ? '#00d4ff' : '#333',
                color: inputMethod === method ? '#000' : '#fff',
                fontWeight: '600',
                textTransform: 'capitalize',
              }}
            >
              {method}
            </button>
          ))}
        </div>

        {inputMethod === 'webs' && (
          <div>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com"
                style={{
                  flex: 1,
                  padding: '12px',
                  borderRadius: '8px',
                  border: '1px solid #333',
                  background: '#1a1a2e',
                  color: '#fff',
                }}
                onKeyDown={(e) => e.key === 'Enter' && addUrl()}
              />
              <button
                onClick={addUrl}
                style={{
                  padding: '12px 20px',
                  borderRadius: '8px',
                  border: 'none',
                  background: '#00d4ff',
                  color: '#000',
                  cursor: 'pointer',
                  fontWeight: '600',
                }}
              >
                Add
              </button>
            </div>
            <div
              style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}
            >
              {urls.map((url: string, i: number) => (
                <div
                  key={i}
                  style={{
                    padding: '12px',
                    background: '#1a1a2e',
                    borderRadius: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <span style={{ color: '#00ff88', fontSize: '14px', wordBreak: 'break-all' }}>
                    {url}
                  </span>
                  <button
                    onClick={() => setUrls(urls.filter((_: string, j: number) => j !== i))}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#ff4444',
                      cursor: 'pointer',
                      fontSize: '18px',
                    }}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
            <button
              onClick={analyzeUrls}
              disabled={urls.length === 0 || loading}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: 'none',
                background: urls.length > 0 ? '#00ff88' : '#333',
                color: '#000',
                cursor: urls.length > 0 ? 'pointer' : 'not-allowed',
                fontWeight: '600',
              }}
            >
              {loading ? 'Analyzing...' : `Analyze ${urls.length} URL(s)`}
            </button>
          </div>
        )}

        {inputMethod === 'files' && (
          <div
            style={{
              border: '2px dashed #333',
              borderRadius: '12px',
              padding: '40px',
              textAlign: 'center',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '32px', marginBottom: '12px' }}>📁</div>
            <div style={{ color: '#888' }}>Drag & drop files here or click to browse</div>
            <div style={{ fontSize: '12px', color: '#555', marginTop: '8px' }}>
              Supports: .js, .ts, .py, .java, .go, .rb, .php, .sql
            </div>
          </div>
        )}

        {inputMethod === 'folder' && (
          <div>
            <input
              type="text"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              placeholder="/path/to/project"
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                marginBottom: '12px',
              }}
            />
            <button
              onClick={scanFolder}
              disabled={!folderPath.trim() || loading}
              style={{
                padding: '12px 20px',
                borderRadius: '8px',
                border: 'none',
                background: folderPath.trim() ? '#00d4ff' : '#333',
                color: '#000',
                cursor: folderPath.trim() ? 'pointer' : 'not-allowed',
                fontWeight: '600',
              }}
            >
              {loading ? 'Scanning...' : 'Scan Folder'}
            </button>
          </div>
        )}

        {inputMethod === 'code' && (
          <div>
            <input
              type="text"
              value={codeFilePath}
              onChange={(e) => setCodeFilePath(e.target.value)}
              placeholder="filename.py (for language detection)"
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                marginBottom: '12px',
              }}
            />
            <textarea
              value={codeInput}
              onChange={(e) => setCodeInput(e.target.value)}
              placeholder="Paste code here for analysis..."
              style={{
                width: '100%',
                minHeight: '200px',
                padding: '12px',
                borderRadius: '8px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                fontFamily: 'monospace',
                marginBottom: '12px',
              }}
            />
            <button
              onClick={analyzeCode}
              disabled={!codeInput.trim() || loading}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: 'none',
                background: codeInput.trim() ? '#00ff88' : '#333',
                color: '#000',
                cursor: codeInput.trim() ? 'pointer' : 'not-allowed',
                fontWeight: '600',
              }}
            >
              {loading ? 'Analyzing...' : 'Analyze Code'}
            </button>
          </div>
        )}

        {inputMethod === 'prompts' && (
          <div>
            <textarea
              value={promptInput}
              onChange={(e) => setPromptInput(e.target.value)}
              placeholder="Enter security testing prompts...&#10;Example: 'How can I test for SQL injection in a login form?'"
              style={{
                width: '100%',
                minHeight: '200px',
                padding: '12px',
                borderRadius: '8px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                marginBottom: '12px',
              }}
            />
            <button
              onClick={processPrompt}
              disabled={!promptInput.trim() || loading}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: 'none',
                background: promptInput.trim() ? '#00ff88' : '#333',
                color: '#000',
                cursor: promptInput.trim() ? 'pointer' : 'not-allowed',
                fontWeight: '600',
              }}
            >
              {loading ? 'Processing...' : 'Process Prompt'}
            </button>
          </div>
        )}

        {error && (
          <div
            style={{
              marginTop: '16px',
              padding: '12px',
              background: 'rgba(255,68,68,0.1)',
              borderRadius: '8px',
              color: '#ff4444',
              fontSize: '14px',
            }}
          >
            Error: {error}
          </div>
        )}

        {results && (
          <div
            style={{
              marginTop: '16px',
              padding: '16px',
              background: '#1a1a2e',
              borderRadius: '8px',
              maxHeight: '300px',
              overflow: 'auto',
            }}
          >
            <div style={{ fontWeight: '600', marginBottom: '12px', color: '#00d4ff' }}>
              Results ({results.type})
            </div>
            <pre
              style={{
                fontSize: '12px',
                color: '#aaa',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {JSON.stringify(results.data, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Burp Suite Integration (Community Edition) */}
      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '8px', color: '#00d4ff' }}>
          🛡️ Burp Suite Integration
        </h3>
        <p style={{ fontSize: '12px', color: '#888', marginBottom: '20px' }}>
          Import Burp Suite JSON exports to analyze captured traffic and identify security
          vulnerabilities
        </p>

        {/* Instructions */}
        <div
          style={{
            marginBottom: '20px',
            padding: '12px',
            background: 'rgba(0, 212, 255, 0.1)',
            borderRadius: '8px',
            fontSize: '13px',
            color: '#aaa',
          }}
        >
          <div style={{ fontWeight: '600', color: '#00d4ff', marginBottom: '8px' }}>
            How to export from Burp Suite:
          </div>
          <ol style={{ margin: 0, paddingLeft: '20px', lineHeight: '1.6' }}>
            <li>Open Burp Suite → Proxy → HTTP History</li>
            <li>Select requests (or Ctrl+A for all)</li>
            <li>
              Click <strong>"Export"</strong> button
            </li>
            <li>
              Choose format: <strong>JSON</strong>
            </li>
            <li>Save the file and upload below</li>
          </ol>
        </div>

        {/* File Upload */}
        <div style={{ marginBottom: '16px' }}>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleBurpFileChange}
            accept=".json"
            style={{ display: 'none' }}
          />
          <button
            onClick={triggerFileSelect}
            style={{
              width: '100%',
              padding: '16px',
              borderRadius: '8px',
              border: burpFile ? '2px solid #00ff88' : '2px dashed #333',
              background: 'transparent',
              color: burpFile ? '#00ff88' : '#888',
              cursor: 'pointer',
              fontWeight: '600',
              fontSize: '14px',
            }}
          >
            {burpFile ? `📄 ${burpFile.name}` : '📁 Click to select JSON export file'}
          </button>
          {burpFile && (
            <div style={{ marginTop: '8px', fontSize: '12px', color: '#666' }}>
              {(burpFile.size / 1024).toFixed(1)} KB • Click to change
            </div>
          )}
        </div>

        {/* Upload Button */}
        <button
          onClick={uploadBurpExport}
          disabled={!burpFile || loading}
          style={{
            width: '100%',
            padding: '14px',
            borderRadius: '8px',
            border: 'none',
            background: burpFile ? '#00ff88' : '#333',
            color: '#000',
            cursor: burpFile ? 'pointer' : 'not-allowed',
            fontWeight: '700',
            fontSize: '15px',
            marginBottom: '12px',
          }}
        >
          {loading ? '⏳ Analyzing...' : '🚀 Analyze Burp Export'}
        </button>

        {/* Status */}
        {burpStatus && (
          <div
            style={{
              marginTop: '12px',
              padding: '10px 14px',
              background: burpStatus.includes('✓')
                ? 'rgba(0,255,136,0.1)'
                : burpStatus.includes('✗')
                  ? 'rgba(255,68,68,0.1)'
                  : 'rgba(0,212,255,0.1)',
              borderRadius: '8px',
              color: burpStatus.includes('✓')
                ? '#00ff88'
                : burpStatus.includes('✗')
                  ? '#ff4444'
                  : '#00d4ff',
              fontSize: '14px',
              fontWeight: '500',
            }}
          >
            {burpStatus}
          </div>
        )}

        {/* Analysis Results Summary */}
        {results?.type === 'burp' && results.data?.summary && (
          <div
            style={{
              marginTop: '16px',
              padding: '12px',
              background: '#1a1a2e',
              borderRadius: '8px',
            }}
          >
            <div style={{ fontWeight: '600', marginBottom: '8px', color: '#00d4ff' }}>
              Analysis Summary
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '8px',
                fontSize: '13px',
              }}
            >
              <div style={{ color: '#888' }}>Total Requests:</div>
              <div style={{ color: '#fff', fontWeight: '600' }}>
                {results.data.summary.total_requests}
              </div>
              <div style={{ color: '#888' }}>API Endpoints:</div>
              <div style={{ color: '#ffaa00', fontWeight: '600' }}>
                {results.data.summary.api_endpoints}
              </div>
              <div style={{ color: '#888' }}>Auth Endpoints:</div>
              <div style={{ color: '#00ff88', fontWeight: '600' }}>
                {results.data.summary.auth_endpoints}
              </div>
              <div style={{ color: '#888' }}>Error Responses:</div>
              <div style={{ color: '#ff4444', fontWeight: '600' }}>
                {results.data.summary.error_responses}
              </div>
              <div style={{ color: '#888' }}>Security Findings:</div>
              <div style={{ color: '#ff8844', fontWeight: '600' }}>
                {results.data.summary.security_findings}
              </div>
            </div>
          </div>
        )}

        {/* Hint */}
        <div
          style={{
            marginTop: '16px',
            padding: '12px',
            background: '#1a1a2e',
            borderRadius: '8px',
            fontSize: '12px',
            color: '#555',
          }}
        >
          💡 Works with Burp Suite Community Edition! No REST API required.
        </div>
        {/* Proxy Configuration (for real-time analysis) */}
        <div
          style={{
            marginTop: '16px',
            padding: '12px',
            background: 'rgba(255, 136, 68, 0.1)',
            borderRadius: '8px',
            border: '1px solid rgba(255, 136, 68, 0.2)',
          }}
        >
          <div style={{ fontWeight: '600', color: '#ff8844', marginBottom: '12px' }}>
            🔗 Real-Time Proxy Mode
          </div>
          <div style={{ fontSize: '12px', color: '#888', marginBottom: '12px' }}>
            Configure SENTINEL-X to route traffic through Burp Suite for live analysis
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="http://localhost:8080"
              id="burp-proxy-url"
              defaultValue="http://localhost:8080"
              style={{
                flex: 1,
                padding: '10px',
                borderRadius: '6px',
                border: '1px solid #333',
                background: '#1a1a2e',
                color: '#fff',
                fontSize: '13px',
              }}
            />
            <button
              onClick={() => {
                const proxyUrl = (document.getElementById('burp-proxy-url') as HTMLInputElement)
                  .value;
                setBurpStatus('Testing proxy connection...');
                fetch('/api/burp/proxy-summary?upstream_proxy=' + encodeURIComponent(proxyUrl))
                  .then((r) => r.json())
                  .then((d) =>
                    setBurpStatus('✓ Proxy connected - ' + d.total_requests + ' requests analyzed'),
                  )
                  .catch((e) => setBurpStatus('✗ Proxy error: ' + e.message));
              }}
              style={{
                padding: '10px 16px',
                borderRadius: '6px',
                border: 'none',
                background: '#ff8844',
                color: '#000',
                cursor: 'pointer',
                fontWeight: '600',
                fontSize: '13px',
              }}
            >
              Connect
            </button>
          </div>
          <div style={{ fontSize: '11px', color: '#666', marginTop: '8px' }}>
            💡 Set browser proxy to SENTINEL-X to capture traffic, then forward to Burp Suite
          </div>
        </div>
      </div>
    </div>
  );
}

// ============ THREAT HUNT PANEL ============
export function ThreatHuntPanel() {
  return (
    <div>
      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '8px' }}>🔍 Threat Hunt</h3>
        <p style={{ fontSize: '13px', color: '#888', marginBottom: '20px' }}>
          Run an agent from the Agents tab to populate threat hunt data. Until then, every counter
          below is 0.
        </p>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '16px',
            marginBottom: '16px',
          }}
        >
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>🎯</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#00d4ff' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>IOCs Found</div>
          </div>
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>👤</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff4444' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Threat Actors</div>
          </div>
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>📡</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff8844' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Campaigns</div>
          </div>
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>⚔️</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ffaa00' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Attacks</div>
          </div>
        </div>
        <div style={{ padding: '24px', textAlign: 'center', color: '#666', fontSize: '13px' }}>
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>🔍</div>
          <div style={{ fontWeight: '600', marginBottom: '4px', color: '#888' }}>
            No threat hunt data yet
          </div>
          <div>Run a threat intelligence agent to populate this view.</div>
        </div>
      </div>
    </div>
  );
}

// ============ SUPPLY CHAIN PANEL ============
export function SupplyChainPanel() {
  return (
    <div>
      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '8px' }}>
          📦 SBOM & Dependency Analysis
        </h3>
        <p style={{ fontSize: '13px', color: '#888', marginBottom: '20px' }}>
          Generate software bill of materials (SBOM) and scan dependencies for known vulnerabilities
          (CVEs). Run an agent from the Agents tab to populate this view.
        </p>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '16px',
            marginBottom: '16px',
          }}
        >
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>📦</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#00d4ff' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Dependencies</div>
          </div>
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>⚠️</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff8844' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Vulnerabilities</div>
          </div>
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>🚨</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ff4444' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Critical</div>
          </div>
          <div
            style={{
              background: '#1a1a2e',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(255,255,255,0.05)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '4px' }}>📋</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ffaa00' }}>0</div>
            <div style={{ fontSize: '12px', color: '#888' }}>License Issues</div>
          </div>
        </div>
        <div style={{ padding: '24px', textAlign: 'center', color: '#666', fontSize: '13px' }}>
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>📦</div>
          <div style={{ fontWeight: '600', marginBottom: '4px', color: '#888' }}>
            No dependency data yet
          </div>
          <div>Run a supply chain agent to generate an SBOM and scan for vulnerabilities.</div>
        </div>
      </div>
    </div>
  );
}

// ============ BUG BOUNTY PANEL (REMOVED — reports are agent knowledge, not a UI section) ============
