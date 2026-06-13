export type ToolState = 'queued' | 'starting' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ToolRun {
  id: string;
  toolName: string;
  params: Record<string, any>;
  state: ToolState;
  startTime: string;
  endTime?: string;
  duration?: string;
  progress?: { current: number; total: number };
  currentTask?: string;
  targetsFound?: number;
  errors?: string[];
  logs: ToolLogEntry[];
  summary?: string;
}

export interface ToolLogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'result';
  message: string;
}

export interface ToolDefinition {
  name: string;
  displayName: string;
  description: string;
  installed: boolean;
  version: string;
  icon: string;
  category: 'recon' | 'scanning' | 'fuzzing' | 'exploit' | 'utility';
  params: ToolParam[];
}

export interface ToolParam {
  name: string;
  label: string;
  type: 'text' | 'select' | 'multiselect' | 'boolean';
  required: boolean;
  defaultValue?: any;
  options?: { label: string; value: string }[];
  placeholder?: string;
}

const TOOLS_API = '/api/tools';

class ToolRunnerServiceClass {
  private runs: ToolRun[] = [];
  private listeners: Set<() => void> = new Set();

  subscribe(listener: () => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    this.listeners.forEach((l) => l());
  }

  getRuns(): ToolRun[] {
    return [...this.runs];
  }

  getRun(id: string): ToolRun | undefined {
    return this.runs.find((r) => r.id === id);
  }

  async getAvailableTools(): Promise<ToolDefinition[]> {
    try {
      const res = await fetch(`${TOOLS_API}/list`);
      if (!res.ok) {
        return [];
      }
      const data = await res.json();
      return (data.tools || []).map((t: any, i: number) => ({
        name: t.name,
        displayName: t.name.charAt(0).toUpperCase() + t.name.slice(1),
        description: `Run ${t.name} scans`,
        installed: t.installed,
        version: t.version || 'unknown',
        icon: ['🔍', '🌐', '⚡', '🎯', '📡'][i % 5],
        category: ['recon', 'scanning', 'fuzzing', 'exploit', 'recon'][i % 5] as any,
        params: this.getDefaultParams(t.name),
      }));
    } catch {
      return [];
    }
  }

  private getDefaultParams(toolName: string): ToolParam[] {
    const common: ToolParam[] = [
      { name: 'target', label: 'Target', type: 'text', required: true, placeholder: 'example.com' },
    ];
    if (toolName === 'gobuster') {
      common.push(
        {
          name: 'mode',
          label: 'Mode',
          type: 'select',
          required: true,
          defaultValue: 'dir',
          options: [
            { label: 'Directory', value: 'dir' },
            { label: 'DNS', value: 'dns' },
            { label: 'VHost', value: 'vhost' },
          ],
        },
        {
          name: 'wordlist',
          label: 'Wordlist',
          type: 'text',
          required: false,
          placeholder: '/path/to/wordlist.txt',
        },
      );
    }
    if (toolName === 'nmap') {
      common.push(
        {
          name: 'ports',
          label: 'Ports',
          type: 'text',
          required: false,
          defaultValue: '1-1000',
          placeholder: '80,443,8080',
        },
        {
          name: 'scan_type',
          label: 'Scan Type',
          type: 'select',
          required: false,
          defaultValue: 'tcp',
          options: [
            { label: 'TCP Connect', value: 'tcp' },
            { label: 'SYN Scan', value: 'syn' },
            { label: 'Service Version', value: 'service' },
          ],
        },
      );
    }
    if (toolName === 'ffuf') {
      common.push(
        {
          name: 'wordlist',
          label: 'Wordlist',
          type: 'text',
          required: false,
          placeholder: '/path/to/wordlist',
        },
        {
          name: 'extension',
          label: 'Extension',
          type: 'text',
          required: false,
          placeholder: 'php,asp,html',
        },
      );
    }
    return common;
  }

  async startTool(toolName: string, params: Record<string, any>): Promise<ToolRun> {
    const run: ToolRun = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      toolName,
      params,
      state: 'queued',
      startTime: new Date().toISOString(),
      logs: [
        {
          timestamp: new Date().toISOString(),
          level: 'info',
          message: `Queued ${toolName} scan...`,
        },
      ],
    };
    this.runs.unshift(run);
    this.notify();

    // Simulate starting
    setTimeout(() => this.updateRun(run.id, { state: 'starting' }), 500);
    setTimeout(
      () => this.updateRun(run.id, { state: 'running', currentTask: 'Initializing...' }),
      1000,
    );

    // Try API call
    try {
      const res = await fetch(`${TOOLS_API}/${toolName}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });
      if (res.ok) {
        const data = await res.json();
        this.addLog(run.id, 'info', 'Tool execution completed');
        this.updateRun(run.id, {
          state: 'completed',
          endTime: new Date().toISOString(),
          summary: `Found ${data.results?.length || 0} results`,
          targetsFound: data.results?.length || 0,
          duration: this.calcDuration(run.startTime),
        });
      } else {
        const err = await res.text();
        this.addLog(run.id, 'error', `HTTP ${res.status}: ${err}`);
        this.updateRun(run.id, {
          state: 'failed',
          endTime: new Date().toISOString(),
          errors: [`HTTP ${res.status}: ${err.substring(0, 200)}`],
          duration: this.calcDuration(run.startTime),
        });
      }
    } catch (e: any) {
      this.addLog(run.id, 'error', `Execution failed: ${e.message}`);
      this.updateRun(run.id, {
        state: 'failed',
        endTime: new Date().toISOString(),
        errors: [e.message],
        duration: this.calcDuration(run.startTime),
      });
    }

    return run;
  }

  cancelRun(id: string) {
    const run = this.runs.find((r) => r.id === id);
    if (run && (run.state === 'queued' || run.state === 'starting' || run.state === 'running')) {
      this.addLog(id, 'warn', 'Cancelled by user');
      this.updateRun(id, {
        state: 'cancelled',
        endTime: new Date().toISOString(),
        duration: this.calcDuration(run.startTime),
      });
      // Also try to cancel on backend
      fetch(`${TOOLS_API}/${run.toolName}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: id }),
      }).catch(() => {});
    }
  }

  clearRun(id: string) {
    this.runs = this.runs.filter((r) => r.id !== id);
    this.notify();
  }

  clearAll() {
    this.runs = [];
    this.notify();
  }

  restartRun(id: string) {
    const run = this.runs.find((r) => r.id === id);
    if (run) {
      this.startTool(run.toolName, run.params);
    }
  }

  private updateRun(id: string, updates: Partial<ToolRun>) {
    const run = this.runs.find((r) => r.id === id);
    if (run) {
      Object.assign(run, updates);
      this.notify();
    }
  }

  private addLog(id: string, level: ToolLogEntry['level'], message: string) {
    const run = this.runs.find((r) => r.id === id);
    if (run) {
      run.logs.push({ timestamp: new Date().toISOString(), level, message });
      this.notify();
    }
  }

  private calcDuration(startTime: string): string {
    const ms = Date.now() - new Date(startTime).getTime();
    const secs = Math.floor(ms / 1000);
    if (secs < 60) {
      return `00:${String(secs).padStart(2, '0')}`;
    }
    const mins = Math.floor(secs / 60);
    return `${String(mins).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`;
  }
}

export const ToolRunnerService = new ToolRunnerServiceClass();
