'use client';

import React, { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import {
  FileText,
  Download,
  Shield,
  AlertTriangle,
  Clock,
  BarChart3,
  Loader2,
  CheckCircle,
  RefreshCw,
  BookOpen,
  Scroll,
  Globe
} from 'lucide-react';

interface ReportCard {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  color: string;
  borderColor: string;
  action: () => Promise<void>;
}

export default function ReportingView() {
  const [downloading, setDownloading] = useState<string | null>(null);
  const [syncStatus, setSyncStatus] = useState<string | null>(null);
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    api.getStats().then(setStats).catch(console.error);
  }, []);

  const handleDownload = async (id: string, fn: () => Promise<void>) => {
    setDownloading(id);
    try {
      await fn();
    } catch (e: any) {
      console.error(`Download failed: ${e.message}`);
    } finally {
      setDownloading(null);
    }
  };

  const handleSyncThreatIntel = async () => {
    setSyncStatus('syncing');
    try {
      await api.syncThreatIntel();
      setSyncStatus('done');
      setTimeout(() => setSyncStatus(null), 3000);
    } catch (e: any) {
      setSyncStatus('error');
      setTimeout(() => setSyncStatus(null), 3000);
    }
  };

  const handleSyncKev = async () => {
    setSyncStatus('kev-syncing');
    try {
      await api.syncKev();
      setSyncStatus('kev-done');
      setTimeout(() => setSyncStatus(null), 3000);
    } catch (e: any) {
      setSyncStatus('kev-error');
      setTimeout(() => setSyncStatus(null), 3000);
    }
  };

  const loadAuditLog = async () => {
    setAuditLoading(true);
    try {
      const data = await api.getAuditLog();
      setAuditLog(data || []);
    } catch (e) {
      console.error('Audit log failed:', e);
    } finally {
      setAuditLoading(false);
    }
  };

  const reports: ReportCard[] = [
    {
      id: 'weekly-digest',
      title: 'Weekly Security Digest',
      description: 'Comprehensive 7-day summary including alert trends, incident resolution metrics, top attacker IPs, and containment actions taken.',
      icon: BarChart3,
      color: 'text-blue-400',
      borderColor: 'border-blue-800/20',
      action: () => api.downloadDigest('week'),
    },
    {
      id: 'monthly-report',
      title: 'Monthly Executive Report',
      description: 'Board-level security posture assessment with MTTR/MTTD trends, risk scores, vulnerability status, and AI-generated executive recommendations.',
      icon: Scroll,
      color: 'text-indigo-400',
      borderColor: 'border-indigo-800/20',
      action: () => api.downloadDigest('month'),
    },
    {
      id: 'threat-intel-report',
      title: 'Threat Intelligence Brief',
      description: 'Latest CVE feeds, CISA Known Exploited Vulnerabilities matches, IP reputation data, and emerging threat actor campaign intelligence.',
      icon: Globe,
      color: 'text-violet-400',
      borderColor: 'border-violet-800/20',
      action: () => api.downloadThreatIntelReport(),
    },
  ];

  return (
    <div className="p-6 space-y-6">
      
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" /> Reports & Intelligence
          </h2>
          <p className="text-xs text-slate-500 mt-1">Generate PDF reports, synchronize threat feeds, and review the cryptographic audit trail.</p>
        </div>
      </div>

      {/* Report Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {reports.map(report => {
          const Icon = report.icon;
          const isDownloading = downloading === report.id;
          return (
            <div key={report.id} className={`bg-slate-900/50 border border-slate-800 ${report.borderColor} rounded-xl p-5 shadow-lg flex flex-col justify-between hover:border-slate-700 transition-all group`}>
              <div>
                <div className="flex items-center gap-2.5 mb-3">
                  <div className={`p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 ${report.color}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="text-xs font-bold text-slate-200">{report.title}</h3>
                </div>
                <p className="text-[10px] text-slate-500 leading-relaxed mb-4">{report.description}</p>
              </div>
              <button
                onClick={() => handleDownload(report.id, report.action)}
                disabled={downloading !== null}
                className="w-full bg-slate-950 hover:bg-blue-600/10 border border-slate-800 hover:border-blue-500/30 text-slate-300 hover:text-blue-300 font-semibold px-4 py-2.5 rounded-lg text-xs transition-all flex items-center justify-center gap-2"
              >
                {isDownloading ? (
                  <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating PDF...</>
                ) : (
                  <><Download className="w-3.5 h-3.5" /> Export PDF Report</>
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Threat Intelligence Sync Section */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4 text-emerald-400" /> Threat Intelligence Feed Sync
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <h4 className="text-xs font-bold text-slate-300 mb-1">CVE & Threat Intel Feeds</h4>
            <p className="text-[10px] text-slate-500 mb-3">Synchronize CVE databases, EPSS scores, and IP reputation feeds.</p>
            <button
              onClick={handleSyncThreatIntel}
              disabled={syncStatus === 'syncing'}
              className="bg-emerald-600/10 border border-emerald-800/30 text-emerald-400 hover:bg-emerald-600/20 font-semibold px-4 py-2 rounded-lg text-[10px] transition-all flex items-center gap-1.5"
            >
              {syncStatus === 'syncing' ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              {syncStatus === 'syncing' ? 'Synchronizing...' : syncStatus === 'done' ? 'Sync Complete ✓' : 'Sync Now'}
            </button>
          </div>
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <h4 className="text-xs font-bold text-slate-300 mb-1">CISA KEV Catalog</h4>
            <p className="text-[10px] text-slate-500 mb-3">Pull latest Known Exploited Vulnerabilities from CISA official feed.</p>
            <button
              onClick={handleSyncKev}
              disabled={syncStatus === 'kev-syncing'}
              className="bg-amber-600/10 border border-amber-800/30 text-amber-400 hover:bg-amber-600/20 font-semibold px-4 py-2 rounded-lg text-[10px] transition-all flex items-center gap-1.5"
            >
              {syncStatus === 'kev-syncing' ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              {syncStatus === 'kev-syncing' ? 'Pulling KEV...' : syncStatus === 'kev-done' ? 'KEV Updated ✓' : 'Sync KEV Feed'}
            </button>
          </div>
        </div>
      </div>

      {/* Quick Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Logs Ingested', value: (stats.total_logs ?? 0).toLocaleString(), icon: BookOpen },
            { label: 'Total Alerts', value: (stats.total_alerts ?? 0).toLocaleString(), icon: AlertTriangle },
            { label: 'Active Blocks', value: (stats.active_blocks ?? 0).toString(), icon: Shield },
            { label: 'Pending Approvals', value: (stats.pending_approvals ?? 0).toString(), icon: Clock },
          ].map((item, idx) => {
            const Icon = item.icon;
            return (
              <div key={idx} className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className="w-4 h-4 text-slate-400" />
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">{item.label}</span>
                </div>
                <p className="text-xl font-bold text-white">{item.value}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* Audit Log Section */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Scroll className="w-4 h-4 text-slate-400" /> Immutable Audit Trail
          </h3>
          <button 
            onClick={loadAuditLog}
            disabled={auditLoading}
            className="text-[10px] text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1 transition-all"
          >
            {auditLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Load Audit Log
          </button>
        </div>
        {auditLog.length > 0 ? (
          <div className="max-h-72 overflow-y-auto border border-slate-800 rounded-lg">
            <table className="w-full">
              <thead className="bg-slate-950 sticky top-0">
                <tr>
                  {['Timestamp', 'Action', 'Target', 'Triggered By', 'Result'].map(h => (
                    <th key={h} className="text-[9px] text-slate-500 font-bold uppercase tracking-wider text-left px-3 py-2 border-b border-slate-800">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {auditLog.slice(0, 50).map((entry, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/10 transition-all">
                    <td className="px-3 py-2 text-[10px] text-slate-500 font-mono">{new Date(entry.timestamp).toLocaleString()}</td>
                    <td className="px-3 py-2 text-[10px] text-slate-300 font-semibold">{entry.action_type}</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-mono">{entry.target}</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400">{entry.triggered_by}</td>
                    <td className="px-3 py-2">
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                        entry.execution_result === 'SUCCESS' ? 'bg-emerald-950/40 text-emerald-400' : 'bg-red-950/40 text-red-400'
                      }`}>{entry.execution_result}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-slate-500 text-xs">
            Click "Load Audit Log" to view the cryptographic audit trail
          </div>
        )}
      </div>
    </div>
  );
}
