export interface Project {
  project_id: string;
  name: string;
  created_at: string;
  project_type?: string;
  findings_count?: number;
  critical_count?: number;
  high_count?: number;
}

export interface HealthStatus {
  status: string;
  version: string;
  providers: string[];
  phase5_enabled?: boolean;
}

export interface AgentModelConfig {
  [agentId: string]: string;
}

export interface Finding {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  location?: string;
  cwe?: string;
  owasp?: string[];
}

export interface ThreatAlert {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  timestamp: string;
  iocs?: string[];
  yara_matches?: string[];
}

export interface SBOMEntry {
  name: string;
  version: string;
  license: string;
  vulnerabilities: string[];
  risk_score: number;
}
