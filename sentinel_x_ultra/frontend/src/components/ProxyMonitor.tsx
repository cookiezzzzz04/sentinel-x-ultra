import { useState, useEffect, useRef } from 'react';
import { StatusIndicator } from './StatusIndicator';

interface ProxyRequest {
  id: string;
  method: string;
  host: string;
  path: string;
  status: number;
  responseTime: number;
  size: number;
  timestamp: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  requestCookies?: string;
  responseHeaders: Record<string, string>;
  responseBody?: string;
  responseLength?: number;
}

interface ProxyStats {
  running: boolean;
  port: number;
  requestsCaptured: number;
  requestsPerMinute: number;
  lastRequestTimestamp: string | null;
}

export function ProxyMonitor() {
  const [requests, setRequests] = useState<ProxyRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<ProxyRequest | null>(null);
  const [inspectTab, setInspectTab] = useState<'request' | 'response'>('request');
  const [stats, setStats] = useState<ProxyStats>({
    running: false,
    port: 8888,
    requestsCaptured: 0,
    requestsPerMinute: 0,
    lastRequestTimestamp: null,
  });
  const [filter, setFilter] = useState('');
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current && isLiveStreaming) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [requests.length, isLiveStreaming]);

  useEffect(() => {
    // Poll proxy stats
    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/burp/proxy-summary');
        if (res.ok) {
          const data = await res.json();
          setStats((prev) => ({
            ...prev,
            running: data.total_requests > 0 || true,
            requestsCaptured: data.total_requests || prev.requestsCaptured,
          }));
        }
      } catch {
        /* ignore */
      }
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const filteredRequests = filter
    ? requests.filter(
        (r) =>
          r.method.toLowerCase().includes(filter.toLowerCase()) ||
          r.host.toLowerCase().includes(filter.toLowerCase()) ||
          r.path.toLowerCase().includes(filter.toLowerCase()),
      )
    : requests;

  const methodColors: Record<string, string> = {
    GET: '#00ff88',
    POST: '#00d4ff',
    PUT: '#ffaa00',
    PATCH: '#ff8844',
    DELETE: '#ff4444',
    HEAD: '#888',
    OPTIONS: '#aa88ff',
  };

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '24px',
        height: 'calc(100vh - 200px)',
      }}
    >
      {/* Left: Proxy Status + Log */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Proxy Status */}
        <div
          style={{
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '16px',
            padding: '20px',
            border: '1px solid rgba(255,255,255,0.05)',
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
            <h3
              style={{
                fontSize: '16px',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              🌐 Proxy Monitor
            </h3>
            <StatusIndicator
              status={stats.running ? 'online' : 'offline'}
              label={stats.running ? 'Running' : 'Stopped'}
              size="md"
            />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
            <div
              style={{
                textAlign: 'center',
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px',
              }}
            >
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>Port</div>
              <div style={{ fontSize: '16px', fontWeight: '700', color: '#00d4ff' }}>
                {stats.port}
              </div>
            </div>
            <div
              style={{
                textAlign: 'center',
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px',
              }}
            >
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>Captured</div>
              <div style={{ fontSize: '16px', fontWeight: '700', color: '#00ff88' }}>
                {stats.requestsCaptured}
              </div>
            </div>
            <div
              style={{
                textAlign: 'center',
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px',
              }}
            >
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>RPM</div>
              <div style={{ fontSize: '16px', fontWeight: '700', color: '#ffaa00' }}>
                {stats.requestsPerMinute}
              </div>
            </div>
            <div
              style={{
                textAlign: 'center',
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px',
              }}
            >
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '4px' }}>Last</div>
              <div style={{ fontSize: '12px', fontWeight: '600', color: '#888' }}>
                {stats.lastRequestTimestamp
                  ? new Date(stats.lastRequestTimestamp).toLocaleTimeString()
                  : '—'}
              </div>
            </div>
          </div>
        </div>

        {/* Search filter */}
        <div
          style={{
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '12px',
            padding: '12px 16px',
            border: '1px solid rgba(255,255,255,0.05)',
            display: 'flex',
            gap: '12px',
            alignItems: 'center',
          }}
        >
          <span style={{ fontSize: '13px', color: '#666' }}>🔍</span>
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by method, host, or path..."
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              color: '#fff',
              fontSize: '13px',
              outline: 'none',
            }}
          />
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            style={{
              padding: '4px 10px',
              borderRadius: '4px',
              border: 'none',
              background: isLiveStreaming ? 'rgba(0,255,136,0.15)' : 'rgba(255,68,68,0.15)',
              color: isLiveStreaming ? '#00ff88' : '#ff4444',
              cursor: 'pointer',
              fontSize: '10px',
              fontWeight: '600',
            }}
          >
            {isLiveStreaming ? '● Live' : '■ Paused'}
          </button>
        </div>

        {/* Live Request Log */}
        <div
          ref={logRef}
          style={{
            flex: 1,
            background: 'rgba(15,15,26,0.95)',
            borderRadius: '12px',
            border: '1px solid rgba(255,255,255,0.05)',
            overflow: 'auto',
          }}
        >
          {filteredRequests.length === 0 ? (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: '#666' }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>🌐</div>
              <div
                style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px', color: '#888' }}
              >
                No requests captured
              </div>
              <div style={{ fontSize: '12px' }}>
                Configure your browser to use this proxy to capture traffic
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {/* Table header */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: '60px 1fr 2fr 70px 80px 70px',
                  padding: '10px 16px',
                  borderBottom: '1px solid rgba(255,255,255,0.05)',
                  fontSize: '10px',
                  color: '#666',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  position: 'sticky',
                  top: 0,
                  background: 'rgba(15,15,26,0.98)',
                }}
              >
                <span>Method</span>
                <span>Host</span>
                <span>Path</span>
                <span>Status</span>
                <span>Time</span>
                <span>Size</span>
              </div>
              {filteredRequests.map((req) => (
                <div
                  key={req.id}
                  onClick={() => setSelectedRequest(req)}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '60px 1fr 2fr 70px 80px 70px',
                    padding: '8px 16px',
                    borderBottom: '1px solid rgba(255,255,255,0.03)',
                    cursor: 'pointer',
                    fontSize: '12px',
                    transition: 'background 0.15s',
                    background:
                      selectedRequest?.id === req.id ? 'rgba(0,212,255,0.08)' : 'transparent',
                  }}
                  onMouseEnter={(e) => {
                    if (selectedRequest?.id !== req.id) {
                      e.currentTarget.style.background = 'rgba(255,255,255,0.03)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (selectedRequest?.id !== req.id) {
                      e.currentTarget.style.background = 'transparent';
                    }
                  }}
                >
                  <span style={{ color: methodColors[req.method] || '#888', fontWeight: '600' }}>
                    {req.method}
                  </span>
                  <span
                    style={{
                      color: '#888',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {req.host}
                  </span>
                  <span
                    style={{
                      color: '#aaa',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      fontFamily: 'monospace',
                      fontSize: '11px',
                    }}
                  >
                    {req.path}
                  </span>
                  <span
                    style={{
                      color:
                        req.status < 300
                          ? '#00ff88'
                          : req.status < 400
                            ? '#00d4ff'
                            : req.status < 500
                              ? '#ffaa00'
                              : '#ff4444',
                      fontWeight: '600',
                    }}
                  >
                    {req.status}
                  </span>
                  <span style={{ color: '#666' }}>{req.responseTime}ms</span>
                  <span style={{ color: '#666' }}>{(req.size / 1024).toFixed(1)} KB</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right: Request Inspector */}
      <div
        style={{
          background: 'rgba(15,15,26,0.95)',
          borderRadius: '16px',
          border: '1px solid rgba(255,255,255,0.05)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {selectedRequest ? (
          <>
            {/* Tabs */}
            <div
              style={{
                display: 'flex',
                borderBottom: '1px solid rgba(255,255,255,0.05)',
                padding: '0 16px',
              }}
            >
              {(['request', 'response'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setInspectTab(tab)}
                  style={{
                    padding: '14px 20px',
                    background: 'transparent',
                    border: 'none',
                    borderBottom:
                      inspectTab === tab ? '2px solid #00d4ff' : '2px solid transparent',
                    color: inspectTab === tab ? '#00d4ff' : '#888',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: inspectTab === tab ? '600' : '400',
                    transition: 'all 0.2s',
                    textTransform: 'capitalize',
                  }}
                >
                  {tab === 'request' ? '📤 Request' : '📥 Response'}
                </button>
              ))}
              <div style={{ flex: 1 }} />
              <button
                onClick={() => setSelectedRequest(null)}
                style={{
                  padding: '14px 12px',
                  background: 'transparent',
                  border: 'none',
                  color: '#888',
                  cursor: 'pointer',
                  fontSize: '14px',
                }}
              >
                ✕
              </button>
            </div>

            {/* Request Summary */}
            <div
              style={{
                padding: '16px',
                background: 'rgba(0,0,0,0.2)',
                borderBottom: '1px solid rgba(255,255,255,0.05)',
                display: 'flex',
                gap: '16px',
                alignItems: 'center',
                fontSize: '12px',
              }}
            >
              <span
                style={{ color: methodColors[selectedRequest.method] || '#888', fontWeight: '700' }}
              >
                {selectedRequest.method}
              </span>
              <span style={{ color: '#888' }}>{selectedRequest.host}</span>
              <span style={{ color: '#aaa', fontFamily: 'monospace' }}>{selectedRequest.path}</span>
              <span
                style={{
                  color: selectedRequest.status < 300 ? '#00ff88' : '#ff4444',
                  fontWeight: '600',
                  marginLeft: 'auto',
                }}
              >
                {selectedRequest.status}
              </span>
            </div>

            {/* Content */}
            <div
              style={{
                flex: 1,
                overflow: 'auto',
                padding: '16px',
                fontFamily: 'monospace',
                fontSize: '12px',
              }}
            >
              {inspectTab === 'request' ? (
                <div>
                  {/* Headers */}
                  <div style={{ marginBottom: '16px' }}>
                    <div
                      style={{
                        color: '#00d4ff',
                        fontWeight: '600',
                        marginBottom: '8px',
                        fontSize: '11px',
                        textTransform: 'uppercase',
                      }}
                    >
                      Headers
                    </div>
                    {Object.entries(selectedRequest.requestHeaders).map(([key, value]) => (
                      <div key={key} style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}>
                        <span style={{ color: '#ffaa00', minWidth: '120px' }}>{key}:</span>
                        <span style={{ color: '#aaa', wordBreak: 'break-all' }}>{value}</span>
                      </div>
                    ))}
                  </div>

                  {/* Cookies */}
                  {selectedRequest.requestCookies && (
                    <div style={{ marginBottom: '16px' }}>
                      <div
                        style={{
                          color: '#ff8844',
                          fontWeight: '600',
                          marginBottom: '8px',
                          fontSize: '11px',
                          textTransform: 'uppercase',
                        }}
                      >
                        Cookies
                      </div>
                      <div
                        style={{
                          color: '#aaa',
                          background: 'rgba(0,0,0,0.2)',
                          padding: '8px',
                          borderRadius: '6px',
                        }}
                      >
                        {selectedRequest.requestCookies}
                      </div>
                    </div>
                  )}

                  {/* Body */}
                  {selectedRequest.requestBody && (
                    <div>
                      <div
                        style={{
                          color: '#00ff88',
                          fontWeight: '600',
                          marginBottom: '8px',
                          fontSize: '11px',
                          textTransform: 'uppercase',
                        }}
                      >
                        Body
                      </div>
                      <div
                        style={{
                          color: '#aaa',
                          background: 'rgba(0,0,0,0.2)',
                          padding: '8px',
                          borderRadius: '6px',
                          whiteSpace: 'pre-wrap',
                          maxHeight: '300px',
                          overflow: 'auto',
                        }}
                      >
                        {selectedRequest.requestBody}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  {/* Status */}
                  <div style={{ marginBottom: '16px' }}>
                    <div
                      style={{
                        color: '#00d4ff',
                        fontWeight: '600',
                        marginBottom: '8px',
                        fontSize: '11px',
                        textTransform: 'uppercase',
                      }}
                    >
                      Status: {selectedRequest.status} • Length:{' '}
                      {selectedRequest.responseLength || selectedRequest.size} bytes
                    </div>
                  </div>

                  {/* Headers */}
                  <div style={{ marginBottom: '16px' }}>
                    <div
                      style={{
                        color: '#00d4ff',
                        fontWeight: '600',
                        marginBottom: '8px',
                        fontSize: '11px',
                        textTransform: 'uppercase',
                      }}
                    >
                      Headers
                    </div>
                    {Object.entries(selectedRequest.responseHeaders).map(([key, value]) => (
                      <div key={key} style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}>
                        <span style={{ color: '#ffaa00', minWidth: '120px' }}>{key}:</span>
                        <span style={{ color: '#aaa', wordBreak: 'break-all' }}>{value}</span>
                      </div>
                    ))}
                  </div>

                  {/* Body */}
                  {selectedRequest.responseBody && (
                    <div>
                      <div
                        style={{
                          color: '#00ff88',
                          fontWeight: '600',
                          marginBottom: '8px',
                          fontSize: '11px',
                          textTransform: 'uppercase',
                        }}
                      >
                        Body
                      </div>
                      <div
                        style={{
                          color: '#aaa',
                          background: 'rgba(0,0,0,0.2)',
                          padding: '8px',
                          borderRadius: '6px',
                          whiteSpace: 'pre-wrap',
                          maxHeight: '400px',
                          overflow: 'auto',
                          fontSize: '11px',
                        }}
                      >
                        {selectedRequest.responseBody.length > 5000
                          ? selectedRequest.responseBody.substring(0, 5000) +
                            '\n\n... [truncated, ' +
                            selectedRequest.responseBody.length +
                            ' chars total]'
                          : selectedRequest.responseBody}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </>
        ) : (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flex: 1,
              color: '#666',
            }}
          >
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔍</div>
              <div
                style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px', color: '#888' }}
              >
                Select a request
              </div>
              <div style={{ fontSize: '12px' }}>Click a request from the log to inspect it</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
