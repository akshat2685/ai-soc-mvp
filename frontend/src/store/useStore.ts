import { create } from 'zustand';

export type ActivePage = 'dashboard' | 'incidents' | 'graph' | 'memory' | 'executive' | 'reporting' | 'threat-intel' | 'settings' | 'federation' | 'chaos';

export interface User {
  username: string;
  role: string;
  tenant_id: string;
  token: string;
}

export interface Incident {
  id: number;
  timestamp: string;
  title: string;
  severity: string;
  status: string;
  correlation_key: string;
  llm_summary?: string;
  verdict: string;
  analyst_notes?: string;
  resolved_at?: string;
  tenant_id: string;
}

export interface Alert {
  id: number;
  timestamp: string;
  title: string;
  severity: string;
  confidence: string;
  confidence_score: number;
  attack_type: string;
  evidence: string;
  attacker_ip: string;
  verdict: string;
  incident_id?: number;
  tenant_id: string;
}

interface StoreState {
  user: User | null;
  currentTenant: string;
  activePage: ActivePage;
  incidents: Incident[];
  alerts: Alert[];
  sidebarOpen: boolean;
  theme: 'dark' | 'light';
  wsMessages: any[];
  
  setAuth: (user: User | null) => void;
  setCurrentTenant: (tenant: string) => void;
  setActivePage: (page: ActivePage) => void;
  setIncidents: (incidents: Incident[]) => void;
  setAlerts: (alerts: Alert[]) => void;
  toggleSidebar: () => void;
  toggleTheme: () => void;
  addWsMessage: (msg: any) => void;
  logout: () => void;
}

export const useStore = create<StoreState>((set) => ({
  user: null,
  currentTenant: 'default',
  activePage: 'dashboard',
  incidents: [],
  alerts: [],
  sidebarOpen: true,
  theme: 'dark',
  wsMessages: [],

  setAuth: (user) => set({ user, currentTenant: user ? user.tenant_id : 'default' }),
  setCurrentTenant: (currentTenant) => set({ currentTenant }),
  setActivePage: (activePage) => set({ activePage }),
  setIncidents: (incidents) => set({ incidents }),
  setAlerts: (alerts) => set({ alerts }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  toggleTheme: () => set((state) => ({ theme: state.theme === 'dark' ? 'light' : 'dark' })),
  addWsMessage: (msg) => set((state) => ({ wsMessages: [msg, ...state.wsMessages].slice(0, 50) })),
  logout: () => set({ user: null, activePage: 'dashboard', incidents: [], alerts: [], wsMessages: [] }),
}));
