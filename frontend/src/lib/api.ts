import { useStore } from '@/store/useStore';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

async function request(path: string, options: RequestInit = {}): Promise<any> {
  const token = useStore.getState().user?.token;
  
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    useStore.getState().logout();
    throw new Error('Unauthorized. Logged out.');
  }

  if (!res.ok) {
    const errText = await res.text();
    let errMsg = `Request failed: ${res.statusText}`;
    try {
      const errJson = JSON.parse(errText);
      errMsg = errJson.detail || errJson.error || errMsg;
    } catch {
      if (errText) errMsg = errText;
    }
    throw new Error(errMsg);
  }

  if (res.status === 204) {
    return null;
  }

  return res.json();
}

async function downloadFile(path: string, filename: string): Promise<void> {
  const token = useStore.getState().user?.token;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`Download failed: ${res.statusText}`);

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export const api = {
  // Authentication
  login: async (username: string, password: string): Promise<any> => {
    return request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },

  // Incidents
  getIncidents: async (): Promise<any> => {
    try {
      return await request('/api/v1/incidents');
    } catch {
      return request('/incidents');
    }
  },
  
  getIncidentDetails: async (id: number): Promise<any> => {
    return request(`/incidents/${id}/details`);
  },
  
  updateIncident: async (id: number, status: string, verdict: string, notes: string): Promise<any> => {
    return request(`/api/v1/incidents/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ status, verdict, analyst_notes: notes }),
    });
  },

  setIncidentVerdict: async (id: number, verdict: string, notes: string): Promise<any> => {
    return request(`/incidents/${id}/verdict`, {
      method: 'POST',
      body: JSON.stringify({ verdict, notes }),
    });
  },

  getIncidentGraph: async (id: number): Promise<any> => {
    return request(`/api/v1/incidents/${id}/graph`);
  },

  // Alerts
  getAlerts: async (): Promise<any> => {
    try {
      return await request('/api/v1/alerts');
    } catch {
      return request('/alerts');
    }
  },

  getAlertDetails: async (id: number): Promise<any> => {
    return request(`/alerts/${id}/details`);
  },

  getAlertInvestigation: async (id: number): Promise<any> => {
    return request(`/alerts/${id}/investigation`);
  },

  triggerAlertInvestigation: async (id: number): Promise<any> => {
    return request(`/alerts/${id}/investigate`, { method: 'POST' });
  },

  // Multi-Agent
  triggerAgentTask: async (task: string): Promise<any> => {
    return request('/api/v1/agents/task', {
      method: 'POST',
      body: JSON.stringify({ task }),
    });
  },

  // Digital Twin
  getTopology: async (): Promise<any> => {
    return request('/api/v1/digital_twin/topology');
  },

  simulateAttack: async (startNodeId: string, attackType: string, riskFactor: number = 0.5): Promise<any> => {
    return request('/api/v1/digital_twin/simulate', {
      method: 'POST',
      body: JSON.stringify({
        start_node_id: startNodeId,
        attack_type: attackType,
        risk_factor: riskFactor,
      }),
    });
  },

  getBlastRadius: async (nodeId: string, nodeLabel: string = 'Host', maxHops: number = 3): Promise<any> => {
    return request(`/api/v1/digital_twin/blast-radius?node_id=${encodeURIComponent(nodeId)}&node_label=${encodeURIComponent(nodeLabel)}&max_hops=${maxHops}`);
  },

  getAttackPaths: async (fromId: string, toId: string): Promise<any> => {
    return request(`/api/v1/digital_twin/attack-paths?from_id=${encodeURIComponent(fromId)}&to_id=${encodeURIComponent(toId)}`);
  },

  cleanupSimulations: async (simId?: string): Promise<any> => {
    const query = simId ? `?sim_id=${encodeURIComponent(simId)}` : '';
    return request(`/api/v1/digital_twin/cleanup${query}`, {
      method: 'DELETE',
    });
  },

  // Executive Metrics
  getExecutiveMetrics: async (): Promise<any> => {
    return request('/api/v1/executive/metrics');
  },

  // Stats
  getStats: async (): Promise<any> => {
    return request('/stats');
  },
  
  // Threat Intelligence
  getCveIntel: async (cveId: string): Promise<any> => {
    return request(`/threat-intel/cve/${cveId}`);
  },

  getIpIntel: async (ip: string): Promise<any> => {
    return request(`/threat-intel/ip/${ip}`);
  },

  syncThreatIntel: async (): Promise<any> => {
    return request('/threat-intel/sync', { method: 'POST' });
  },

  syncKev: async (): Promise<any> => {
    return request('/threat-intel/kev/sync', { method: 'POST' });
  },

  // Reports
  downloadAlertReport: async (alertId: number): Promise<void> => {
    return downloadFile(`/alerts/${alertId}/report.pdf`, `edysor_alert_${alertId}.pdf`);
  },

  downloadDigest: async (period: string = 'week'): Promise<void> => {
    return downloadFile(`/api/v1/reports/digest?period=${period}`, `edysor_digest_${period}.pdf`);
  },

  downloadThreatIntelReport: async (): Promise<void> => {
    return downloadFile('/threat-intel/report.pdf', 'edysor_threat_intel.pdf');
  },

  // AI Chat
  chat: async (query: string): Promise<any> => {
    return request('/chat', {
      method: 'POST',
      body: JSON.stringify({ query }),
    });
  },

  // Telemetry
  triggerLogGeneration: async (count: number = 100): Promise<any> => {
    return request('/api/v1/telemetry/generate', {
      method: 'POST',
      body: JSON.stringify({ count }),
    });
  },

  // MITRE Mappings
  getMitreMappings: async (): Promise<any> => {
    return request('/mitre/mappings');
  },

  // Audit Log
  getAuditLog: async (): Promise<any> => {
    return request('/audit-log');
  },

  // Approvals
  getApprovals: async (): Promise<any> => {
    return request('/approvals');
  },
};
