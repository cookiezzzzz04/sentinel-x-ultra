import { useState } from 'react';
import type { ThreatAlert } from './types';
import { StatCard } from './StatCard';

export function ThreatHuntView() {
  const [alerts] = useState<ThreatAlert[]>([
    {
      id: '1',
      type: 'malware',
      severity: 'CRITICAL',
      title: 'Suspicious PowerShell Execution',
      description: 'Base64 encoded command detected in process creation',
      timestamp: '2024-01-15T10:30:00.000Z',
      iocs: ['192.168.1.105', 'malware.exe'],
      yara_matches: ['meterpreter', 'covenant'],
    },
    {
      id: '2',
      type: 'network',
      severity: 'HIGH',
      title: 'C2 Communication Detected',
      description: 'Beaconing behavior to known malicious IP',
      timestamp: '2024-01-15T10:25:00.000Z',
      iocs: ['185.220.101.34'],
      yara_matches: ['apt_threat'],
    },
    {
      id: '3',
      type: 'anomaly',
      severity: 'MEDIUM',
      title: 'Unusual Login Pattern',
      description: 'Login from multiple geographies within 1 hour',
      timestamp: '2024-01-15T10:20:00.000Z',
      iocs: [],
      yara_matches: [],
    },
  ]);

  return (
    <div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '16px',
          marginBottom: '24px',
        }}
      >
        <StatCard label="Active IOCs" value="47" icon="🎯" color="#ff4444" trend="+12" />
        <StatCard label="YARA Rules" value="156" icon="📜" color="#aa88ff" />
        <StatCard label="Threat Feeds" value="8" icon="📡" color="#00d4ff" />
        <StatCard label="IOC Matches" value="3" icon="⚠️" color="#ffaa00" />
      </div>

      <div
        style={{
          background: 'rgba(15, 15, 26, 0.95)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid rgba(255,255,255,0.05)',
          marginBottom: '24px',
        }}
      >
        <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>
          Threat Hunting Actions
        </h3>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            style={{
              background: 'linear-gradient(135deg, rgba(255, 68, 68, 0.2), rgba(255, 68, 68, 0.1))',
              border: '1px solid #ff4444',
              color: '#ff4444',
              padding: '12px 20px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: '600',
            }}
          >
            🔍 Scan for IOCs
          </button>
          <button
            style={{
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.1)',
              color: '#888',
              padding: '12px 20px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '13px',
            }}
          >
            📜 Deploy YARA Rules
          </button>
          <button
            style={{
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.1)',
              color: '#888',
              padding: '12px 20px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '13px',
            }}
          >
            📊 Enrich from VirusTotal
          </button>
        </div>
      </div>

      <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px', color: '#888' }}>
        Active Alerts
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {alerts.map((alert) => (
          <div
            key={alert.id}
            style={{
              background: 'rgba(15, 15, 26, 0.95)',
              borderRadius: '12px',
              padding: '20px',
              border: `1px solid ${alert.severity === 'CRITICAL' ? '#ff4444' : alert.severity === 'HIGH' ? '#ff8844' : '#ffaa00'}30`,
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '20px' }}>
                  {alert.type === 'malware' ? '🦠' : alert.type === 'network' ? '🌐' : '⚠️'}
                </span>
                <h4 style={{ fontSize: '15px', fontWeight: '600' }}>{alert.title}</h4>
              </div>
              <span
                style={{
                  background: `${alert.severity === 'CRITICAL' ? '#ff4444' : alert.severity === 'HIGH' ? '#ff8844' : '#ffaa00'}20`,
                  color:
                    alert.severity === 'CRITICAL'
                      ? '#ff4444'
                      : alert.severity === 'HIGH'
                        ? '#ff8844'
                        : '#ffaa00',
                  fontSize: '11px',
                  fontWeight: '600',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  textTransform: 'uppercase',
                }}
              >
                {alert.severity}
              </span>
            </div>
            <p style={{ fontSize: '13px', color: '#888', marginBottom: '12px' }}>
              {alert.description}
            </p>
            <div style={{ display: 'flex', gap: '16px', fontSize: '12px' }}>
              <span style={{ color: '#666' }}>🕐 {new Date(alert.timestamp).toLocaleString()}</span>
              {alert.iocs && alert.iocs.length > 0 && (
                <span style={{ color: '#00d4ff' }}>📍 IOCs: {alert.iocs.join(', ')}</span>
              )}
              {alert.yara_matches && alert.yara_matches.length > 0 && (
                <span style={{ color: '#aa88ff' }}>📜 YARA: {alert.yara_matches.join(', ')}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
