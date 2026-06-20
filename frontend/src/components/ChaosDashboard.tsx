import React, { useState, useEffect } from 'react';
import { AlertTriangle, Database, Zap, Activity, ShieldAlert, Cpu } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, AreaChart, Area } from 'recharts';
import { api } from '@/lib/api';

export default function ChaosDashboard() {
  const [chaosData, setChaosData] = useState<any[]>([]);

  useEffect(() => {
    // Mocking Chaos Engineering resilience data
    const data = Array.from({ length: 15 }).map((_, i) => ({
      time: new Date(Date.now() - (15 - i) * 60000).toLocaleTimeString(),
      latency_ms: 50 + (Math.random() * 20) + (i === 7 ? 400 : 0), // Simulate a network spike
      db_health: i === 10 ? 0 : 100, // Simulate DB drop
      mttd_ms: 120 + (Math.random() * 10) + (i === 7 ? 50 : 0)
    }));
    setChaosData(data);
  }, []);

  const triggerChaos = () => {
    alert("Warning: Triggering Database Drop simulation! (Mocked)");
  };

  return (
    <div className="p-6 h-[calc(100vh-4rem)] overflow-y-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Zap className="w-6 h-6 text-amber-500" />
            Chaos Engineering & Resilience Lab
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time monitoring of automated failure injections (Simian Army).
          </p>
        </div>
        <button 
          onClick={triggerChaos}
          className="bg-red-600/20 hover:bg-red-600/40 border border-red-500/50 text-red-400 px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2"
        >
          <ShieldAlert className="w-4 h-4" />
          Trigger Chaos (Drop DB)
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Active Enclave', value: 'AMD SEV-SNP', icon: Cpu, color: 'text-blue-400' },
          { label: 'Network Latency Penalty', value: '+12ms', icon: Activity, color: 'text-emerald-400' },
          { label: 'DB Drop Recovery Time', value: '45ms', icon: Database, color: 'text-amber-400' },
        ].map((stat, idx) => {
          const Icon = stat.icon;
          return (
            <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg">
              <div className="flex items-center gap-3 mb-2">
                <div className={`p-2 rounded bg-slate-950 border border-slate-800 ${stat.color}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{stat.label}</span>
              </div>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg h-80">
          <h3 className="text-sm font-bold text-slate-300 mb-4 uppercase tracking-wider">System Latency (Under Chaos)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chaosData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorLatency" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" tick={{fill: '#64748b', fontSize: 10}} />
              <YAxis tick={{fill: '#64748b', fontSize: 10}} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
              <Area type="monotone" dataKey="latency_ms" stroke="#f59e0b" fillOpacity={1} fill="url(#colorLatency)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg h-80">
          <h3 className="text-sm font-bold text-slate-300 mb-4 uppercase tracking-wider">Detection Speed (MTTD under load)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chaosData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" tick={{fill: '#64748b', fontSize: 10}} />
              <YAxis domain={['auto', 'auto']} tick={{fill: '#64748b', fontSize: 10}} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
              <Line type="monotone" dataKey="mttd_ms" stroke="#10b981" strokeWidth={3} dot={{ fill: '#10b981', strokeWidth: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
