'use client';

import React, { useEffect, useState } from 'react';
import { useStore, ActivePage } from '@/store/useStore';
import { api } from '@/lib/api';
import CopilotDrawer from '@/components/CopilotDrawer';
import FederationDashboard from '@/components/FederationDashboard';
import ChaosDashboard from '@/components/ChaosDashboard';
import { 
  Shield, 
  LayoutDashboard, 
  AlertTriangle, 
  Network, 
  Database, 
  BarChart3, 
  Settings, 
  LogOut, 
  User as UserIcon, 
  Globe, 
  Menu, 
  X,
  Radio,
  Bell
} from 'lucide-react';

interface ShellProps {
  children: React.ReactNode;
}

export default function DashboardShell({ children }: ShellProps) {
  const { 
    user, 
    setAuth, 
    activePage, 
    setActivePage, 
    currentTenant, 
    setCurrentTenant, 
    sidebarOpen, 
    toggleSidebar,
    addWsMessage
  } = useStore();

  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin');
  const [loginError, setLoginError] = useState('');
  const [loading, setLoading] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);

  // WebSocket Connection
  useEffect(() => {
    if (!user) return;

    let ws: WebSocket;
    const connectWs = () => {
      try {
        const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws';
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
          log.info('WebSocket Connected');
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            addWsMessage(data);
            
            // Show inline toast notification
            setNotifications(prev => [data, ...prev].slice(0, 5));
          } catch (e) {
            log.warning('WS parse error:', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          // Try to reconnect in 5 seconds
          setTimeout(connectWs, 5000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (err) {
        log.warning('WS creation error:', err);
      }
    };

    connectWs();
    return () => {
      if (ws) ws.close();
    };
  }, [user, addWsMessage]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setLoading(true);
    try {
      const res = await api.login(username, password);
      setAuth({
        username: res.username,
        role: res.role,
        tenant_id: res.tenant_id || 'default',
        token: res.token
      });
    } catch (err: any) {
      setLoginError(err.message || 'Login failed. Check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  // Login View
  if (!user) {
    return (
      <div className="min-h-screen bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-slate-900 via-zinc-950 to-black text-white flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-slate-900/60 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-600"></div>
          
          <div className="flex flex-col items-center mb-8">
            <div className="w-14 h-14 bg-gradient-to-tr from-blue-600 to-indigo-500 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20 mb-3">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-slate-400">
              EDYSOR AI-SOC
            </h1>
            <p className="text-sm text-slate-400 mt-1">Autonomous Detection & Response</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-blue-500/80 transition-all text-white"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-blue-500/80 transition-all text-white"
                required
              />
            </div>

            {loginError && (
              <div className="text-xs bg-red-950/40 border border-red-800/80 text-red-400 px-4 py-3 rounded-xl">
                {loginError}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold py-3 rounded-xl transition-all shadow-lg shadow-indigo-600/20 active:scale-[0.98] disabled:opacity-50"
            >
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'incidents', label: 'Incidents & Triage', icon: AlertTriangle },
    { id: 'graph', label: 'Digital Twin Graph', icon: Network },
    { id: 'memory', label: 'Memory Explorer', icon: Database },
    { id: 'executive', label: 'Executive Metrics', icon: BarChart3 },
    { id: 'federation', label: 'Federated Mesh', icon: Globe },
    { id: 'chaos', label: 'Resilience Lab', icon: Zap },
    { id: 'reporting', label: 'Reports & Intel', icon: Globe },
    { id: 'settings', label: 'SOC Settings', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex overflow-hidden">
      
      {/* Real-time alert notifications overlay */}
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full">
        {notifications.map((notif, idx) => (
          <div 
            key={idx} 
            className="bg-slate-900/90 border border-slate-800 backdrop-blur-md p-4 rounded-xl shadow-xl flex gap-3 animate-slide-in relative overflow-hidden"
          >
            <div className="absolute top-0 left-0 h-full w-1 bg-red-500"></div>
            <div className="w-8 h-8 rounded-full bg-red-950/40 border border-red-800/30 flex items-center justify-center text-red-400 flex-shrink-0">
              <AlertTriangle className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-bold text-slate-200 truncate">{notif.event_type || 'New Ingested Log'}</p>
              <p className="text-[11px] text-slate-400 truncate">{notif.endpoint || notif.source_ip || 'Details matching baseline rules'}</p>
            </div>
            <button 
              onClick={() => setNotifications(prev => prev.filter((_, i) => i !== idx))}
              className="text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>

      {/* Sidebar Navigation */}
      <aside className={`bg-slate-900 border-r border-slate-800 w-64 flex-shrink-0 flex flex-col transition-all duration-300 ${sidebarOpen ? 'ml-0' : '-ml-64'}`}>
        <div className="h-16 px-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="font-bold text-sm bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-300">EDYSOR AI-SOC</span>
          </div>
          <button onClick={toggleSidebar} className="lg:hidden text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tenant Selector */}
        <div className="p-4 border-b border-slate-800">
          <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1">
            <Globe className="w-3 h-3" /> Tenant Sandbox
          </label>
          <select
            value={currentTenant}
            onChange={e => setCurrentTenant(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-blue-500 transition-all text-slate-200"
          >
            <option value="default">Default Tenant</option>
            <option value="fintech_corp">FinTech Corp</option>
            <option value="healthlink">HealthLink</option>
            <option value="defense_net">DefenseNet</option>
          </select>
        </div>

        <nav className="flex-1 py-4 px-3 space-y-1">
          {navItems.map(item => {
            const Icon = item.icon;
            const active = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id as ActivePage)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                  active 
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/10' 
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-white' : 'text-slate-400'}`} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* User Info / Logout */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/20 flex flex-col gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-blue-400">
              <UserIcon className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-bold text-slate-200 truncate">{user.username}</p>
              <p className="text-[10px] text-slate-400 uppercase tracking-wider">{user.role}</p>
            </div>
          </div>
          <button 
            onClick={() => useStore.getState().logout()}
            className="w-full flex items-center justify-center gap-2 bg-slate-950 hover:bg-red-950/20 text-slate-400 hover:text-red-400 border border-slate-800 rounded-lg py-2 text-xs font-semibold transition-all"
          >
            <LogOut className="w-3.5 h-3.5" /> Log Out
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 border-b border-slate-800 bg-slate-900/60 backdrop-blur-md flex items-center justify-between px-6 z-10 flex-shrink-0">
          <div className="flex items-center gap-4">
            {!sidebarOpen && (
              <button onClick={toggleSidebar} className="text-slate-400 hover:text-white transition-all">
                <Menu className="w-5 h-5" />
              </button>
            )}
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              {navItems.find(n => n.id === activePage)?.label || 'System'}
            </h2>
          </div>

          <div className="flex items-center gap-4">
            {/* Live Feed WebSocket indicator */}
            <div className="flex items-center gap-2 border border-slate-800 bg-slate-950/50 px-3 py-1.5 rounded-full">
              <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-green-500 animate-pulse' : 'text-red-500'}`} />
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                {wsConnected ? 'Live Feed Active' : 'Disconnected'}
              </span>
            </div>
          </div>
        </header>

        {/* Dynamic page content */}
        <main className="flex-1 overflow-y-auto bg-slate-950 relative">
          {children}
          <CopilotDrawer />
        </main>
      </div>
    </div>
  );
}

// Simple client-side logger dummy to prevent build errors
const log = {
  info: (msg: string, ...args: any[]) => console.log(`[INFO] ${msg}`, ...args),
  warning: (msg: string, ...args: any[]) => console.warn(`[WARN] ${msg}`, ...args)
};
