'use client';

import React, { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { 
  ShieldCheck, 
  TrendingUp,
  TrendingDown,
  Clock, 
  Activity, 
  AlertTriangle,
  Target,
  Zap,
  Award,
  FileText,
  Download,
  Brain,
  BarChart3
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  AreaChart, Area,
  RadialBarChart, RadialBar, Legend
} from 'recharts';

const CHART_COLORS = ['#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#ec4899'];
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

export default function ExecutiveDashboardView() {
  const [metrics, setMetrics] = useState<any>(null);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [execMetrics, statsData] = await Promise.allSettled([
          api.getExecutiveMetrics(),
          api.getStats(),
        ]);

        if (execMetrics.status === 'fulfilled') setMetrics(execMetrics.value);
        if (statsData.status === 'fulfilled') setStats(statsData.value);
      } catch (e) {
        console.error('Executive fetch failed:', e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleDownload = async (type: string) => {
    setDownloading(type);
    try {
      if (type === 'weekly') await api.downloadDigest('week');
      else if (type === 'monthly') await api.downloadDigest('month');
      else if (type === 'threat-intel') await api.downloadThreatIntelReport();
    } catch (e: any) {
      console.error(`Download failed: ${e.message}`);
    } finally {
      setDownloading(null);
    }
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
          <span className="text-xs text-slate-400 font-semibold">Loading executive metrics...</span>
        </div>
      </div>
    );
  }

  const postureScore = metrics?.posture_score ?? 72;
  const mttrHours = metrics?.mttr_hours ?? 0;
  const mttdHours = metrics?.mttd_hours ?? 0;
  const openInc = metrics?.open_incidents ?? 0;
  const resolvedInc = metrics?.resolved_incidents ?? 0;
  const assetRisk = metrics?.asset_risk_score ?? 0;
  const execSummary = metrics?.executive_summary ?? 'Executive summary unavailable. Backend may be offline.';
  const threatTrends = metrics?.threat_trends ?? [];
  const topTargets = metrics?.top_targets ?? [];

  // Attack distribution from stats
  const distribution = stats?.attack_distribution ?? {};
  const distributionData = Object.entries(distribution).map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value: value as number
  }));

  // Posture radial data
  const postureData = [{ name: 'Posture', value: postureScore, fill: postureScore >= 70 ? '#22c55e' : postureScore >= 40 ? '#eab308' : '#ef4444' }];

  // Threat trends chart data
  const trendData = threatTrends.map((t: any) => ({
    day: new Date(t.day).toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }),
    alerts: t.c
  }));

  const kpiCards = [
    { 
      label: 'Security Posture', 
      value: `${postureScore}/100`,
      desc: postureScore >= 70 ? 'Healthy posture' : postureScore >= 40 ? 'Needs improvement' : 'Critical risk', 
      icon: ShieldCheck, 
      color: postureScore >= 70 ? 'text-emerald-400' : postureScore >= 40 ? 'text-amber-400' : 'text-red-400',
      bgGlow: postureScore >= 70 ? 'shadow-emerald-500/5' : 'shadow-amber-500/5'
    },
    { 
      label: 'MTTR', 
      value: `${mttrHours.toFixed(1)}h`, 
      desc: 'Mean Time to Respond', 
      icon: Clock, 
      color: 'text-blue-400',
      bgGlow: 'shadow-blue-500/5'
    },
    { 
      label: 'MTTD', 
      value: `${mttdHours.toFixed(1)}h`, 
      desc: 'Mean Time to Detect', 
      icon: Activity, 
      color: 'text-indigo-400',
      bgGlow: 'shadow-indigo-500/5'
    },
    { 
      label: 'Open Incidents', 
      value: openInc.toString(), 
      desc: `${resolvedInc} resolved total`, 
      icon: AlertTriangle, 
      color: openInc > 5 ? 'text-red-400' : 'text-amber-400',
      bgGlow: 'shadow-amber-500/5'
    },
    { 
      label: 'Asset Risk Score', 
      value: `${assetRisk}`, 
      desc: 'Composite risk from vulns & assets', 
      icon: Target, 
      color: assetRisk > 50 ? 'text-red-400' : 'text-emerald-400',
      bgGlow: 'shadow-violet-500/5'
    },
    { 
      label: 'Total Alerts', 
      value: (stats?.total_alerts ?? 0).toLocaleString(), 
      desc: `${stats?.total_blocked ?? 0} blocked responses`, 
      icon: Zap, 
      color: 'text-violet-400',
      bgGlow: 'shadow-violet-500/5'
    },
  ];

  return (
    <div className="p-6 space-y-6">
      
      {/* AI Executive Summary Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 border border-indigo-900/30 rounded-2xl p-6 relative overflow-hidden shadow-xl">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(99,102,241,0.08),transparent_70%)]"></div>
        <div className="relative flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center flex-shrink-0">
            <Brain className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="flex-1">
            <h3 className="text-xs font-bold text-indigo-300 uppercase tracking-wider mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse"></span>
              EDYSOR AI Executive Summary
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed">{execSummary}</p>
          </div>
          <div className="flex-shrink-0 ml-4 border-l border-indigo-500/20 pl-4">
            <button
              onClick={async () => {
                if (confirm('CRITICAL WARNING: This will isolate the network and wipe the LLM context. Proceed?')) {
                  try {
                    const res = await fetch('http://localhost:8000/api/v1/emergency/panic', { method: 'POST' });
                    const data = await res.json();
                    alert(`Panic Triggered: \n${data.actions_taken.join(', ')}`);
                  } catch (e) {
                    alert('Failed to trigger panic: ' + e);
                  }
                }
              }}
              className="px-4 py-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 font-bold text-xs rounded border border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.3)] transition-all flex items-center gap-2 uppercase tracking-widest"
            >
              <AlertTriangle className="w-4 h-4" />
              Panic Button
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpiCards.map((kpi, idx) => {
          const Icon = kpi.icon;
          return (
            <div 
              key={idx} 
              className={`bg-slate-900/60 border border-slate-800 hover:border-slate-700 p-4 rounded-xl shadow-lg ${kpi.bgGlow} transition-all duration-200 group`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className={`p-2 rounded-lg bg-slate-950/80 border border-slate-800 ${kpi.color}`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
              <p className="text-xl font-bold text-white">{kpi.value}</p>
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mt-1">{kpi.label}</p>
              <p className="text-[9px] text-slate-500 mt-0.5">{kpi.desc}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Threat Trends Chart */}
        <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-4">
            <BarChart3 className="w-4 h-4 text-blue-400" /> 7-Day Alert Trend
          </h3>
          <div className="h-64">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="day" tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={{ stroke: '#334155' }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={{ stroke: '#334155' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px', fontSize: '11px' }}
                    labelStyle={{ color: '#e2e8f0', fontWeight: 'bold' }}
                    itemStyle={{ color: '#3b82f6' }}
                  />
                  <Area type="monotone" dataKey="alerts" stroke="#3b82f6" strokeWidth={2} fill="url(#alertGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs">
                <TrendingDown className="w-5 h-5 mr-2 opacity-40" /> No trend data available yet
              </div>
            )}
          </div>
        </div>

        {/* Security Posture Gauge */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" /> Security Posture
          </h3>
          <div className="flex-1 flex items-center justify-center">
            <ResponsiveContainer width="100%" height={200}>
              <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="90%" barSize={14} data={postureData} startAngle={180} endAngle={0}>
                <RadialBar
                  background={{ fill: '#1e293b' }}
                  dataKey="value"
                  cornerRadius={8}
                />
              </RadialBarChart>
            </ResponsiveContainer>
          </div>
          <div className="text-center -mt-8">
            <p className={`text-3xl font-bold ${postureScore >= 70 ? 'text-emerald-400' : postureScore >= 40 ? 'text-amber-400' : 'text-red-400'}`}>
              {postureScore}
            </p>
            <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider mt-1">
              {postureScore >= 70 ? 'Healthy' : postureScore >= 40 ? 'Moderate Risk' : 'Critical'}
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Attack Distribution Pie */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-4">
            <Target className="w-4 h-4 text-violet-400" /> Attack Type Distribution
          </h3>
          <div className="h-64 flex items-center justify-center">
            {distributionData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distributionData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                    label={({ name, percent }) => `${name} (${((percent ?? 0) * 100).toFixed(0)}%)`}
                    labelLine={{ stroke: '#475569', strokeWidth: 1 }}
                  >
                    {distributionData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px', fontSize: '11px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <span className="text-xs text-slate-500">No attack data available</span>
            )}
          </div>
        </div>

        {/* Top Targeted IPs */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-rose-400" /> Top Attacker IPs
          </h3>
          {topTargets.length > 0 ? (
            <div className="space-y-3">
              {topTargets.map((target: any, idx: number) => {
                const maxCount = topTargets[0]?.c || 1;
                const barWidth = Math.max(5, (target.c / maxCount) * 100);
                return (
                  <div key={idx} className="group">
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-mono text-slate-300 group-hover:text-white transition-all">{target.attacker_ip}</span>
                      <span className="text-[10px] font-bold text-slate-400">{target.c} alerts</span>
                    </div>
                    <div className="h-2 w-full bg-slate-950 border border-slate-800 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-rose-600 to-rose-400 rounded-full transition-all duration-500"
                        style={{ width: `${barWidth}%` }}
                      ></div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-48 text-xs text-slate-500">
              No attacker data available
            </div>
          )}
        </div>
      </div>

      {/* Report Downloads */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-4">
          <FileText className="w-4 h-4 text-blue-400" /> Report Generation & Export
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { id: 'weekly', label: 'Weekly Security Digest', desc: 'Comprehensive 7-day summary with trends, incidents, and recommendations' },
            { id: 'monthly', label: 'Monthly Executive Report', desc: 'Board-level security posture assessment and risk analysis' },
            { id: 'threat-intel', label: 'Threat Intelligence Brief', desc: 'Latest CVE feeds, CISA KEV matches, and IP reputation intelligence' },
          ].map(report => (
            <div key={report.id} className="bg-slate-950/60 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all group">
              <h4 className="text-xs font-bold text-slate-200 mb-1">{report.label}</h4>
              <p className="text-[10px] text-slate-500 mb-3 leading-relaxed">{report.desc}</p>
              <button
                onClick={() => handleDownload(report.id)}
                disabled={downloading !== null}
                className="w-full bg-slate-900 hover:bg-blue-600/20 border border-slate-800 hover:border-blue-500/40 text-slate-300 hover:text-blue-300 font-semibold px-3 py-2 rounded-lg text-[10px] transition-all flex items-center justify-center gap-1.5"
              >
                <Download className="w-3 h-3" />
                {downloading === report.id ? 'Generating...' : 'Export PDF'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* MITRE Coverage Matrix */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-4">
          <Award className="w-4 h-4 text-emerald-400" /> MITRE ATT&CK Detection Coverage
        </h3>
        <div className="space-y-3">
          {[
            { area: 'Credential Access (TA0006)', score: 94, tactics: 'T1110, T1078, T1528' },
            { area: 'Initial Access (TA0001)', score: 87, tactics: 'T1190, T1566, T1133' },
            { area: 'Lateral Movement (TA0008)', score: 78, tactics: 'T1021, T1570, T1080' },
            { area: 'Exfiltration (TA0010)', score: 92, tactics: 'T1041, T1048, T1567' },
            { area: 'Persistence (TA0003)', score: 71, tactics: 'T1053, T1136, T1543' },
          ].map((item, idx) => (
            <div key={idx} className="group">
              <div className="flex justify-between items-center mb-1.5">
                <div>
                  <span className="text-xs font-semibold text-slate-300">{item.area}</span>
                  <span className="text-[9px] text-slate-500 ml-2">{item.tactics}</span>
                </div>
                <span className={`text-xs font-bold ${item.score >= 85 ? 'text-emerald-400' : item.score >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
                  {item.score}%
                </span>
              </div>
              <div className="h-2 w-full bg-slate-950 border border-slate-800 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-700 ${
                    item.score >= 85 ? 'bg-gradient-to-r from-emerald-600 to-emerald-400' : 
                    item.score >= 70 ? 'bg-gradient-to-r from-amber-600 to-amber-400' : 
                    'bg-gradient-to-r from-red-600 to-red-400'
                  }`}
                  style={{ width: `${item.score}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
