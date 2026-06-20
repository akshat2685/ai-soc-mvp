'use client';

import React, { useState, useEffect } from 'react';
import { useStore, Incident } from '@/store/useStore';
import { api } from '@/lib/api';
import { 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Sparkles, 
  Send,
  Zap,
  Lock,
  UserX,
  FileSpreadsheet,
  Search,
  Brain,
  Shield,
  ChevronRight,
  FileText,
  Target,
  Eye,
  X,
  Loader2,
  Download
} from 'lucide-react';
import XAIPanel from './XAIPanel';
import MultiplayerCursor from './MultiplayerCursor';
import VoiceCommandBar from './VoiceCommandBar';

type DetailTab = 'summary' | 'investigation' | 'timeline' | 'mitre' | 'soar';

export default function IncidentsView() {
  const { incidents, setIncidents } = useStore();
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [notes, setNotes] = useState('');
  const [updating, setUpdating] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [soarLog, setSoarLog] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<DetailTab>('summary');
  const [incidentDetails, setIncidentDetails] = useState<any>(null);
  const [investigation, setInvestigation] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Load incident details when selected
  useEffect(() => {
    if (!selectedIncident) return;
    setDetailLoading(true);
    api.getIncidentDetails(selectedIncident.id)
      .then(data => setIncidentDetails(data))
      .catch(e => console.error('Detail fetch failed:', e))
      .finally(() => setDetailLoading(false));
  }, [selectedIncident?.id]);

  const handleSelectIncident = (inc: Incident) => {
    setSelectedIncident(inc);
    setNotes(inc.analyst_notes || '');
    setActiveTab('summary');
    setInvestigation(null);
    setIncidentDetails(null);
  };

  const handleUpdateIncident = async (status: string, verdict: string) => {
    if (!selectedIncident) return;
    setUpdating(true);
    try {
      await api.updateIncident(selectedIncident.id, status, verdict, notes);
      const updated = await api.getIncidents();
      setIncidents(updated);
      setSelectedIncident(prev => prev ? { ...prev, status, verdict, analyst_notes: notes } : null);
      setSoarLog(prev => [`System: Updated incident ${selectedIncident.id} → ${status} (${verdict})`, ...prev]);
    } catch (e: any) {
      console.error(e);
    } finally {
      setUpdating(false);
    }
  };

  const handleRunInvestigation = async () => {
    if (!selectedIncident) return;
    setInvestigationLoading(true);
    setActiveTab('investigation');
    try {
      const taskDesc = `Investigate Incident ${selectedIncident.id}: ${selectedIncident.title}. Correlation key: ${selectedIncident.correlation_key}.`;
      const result = await api.triggerAgentTask(taskDesc);
      setInvestigation(result);
      setSoarLog(prev => [`Agent Team: Investigation complete for incident ${selectedIncident.id}`, ...prev]);
    } catch (e: any) {
      setInvestigation({ error: e.message, messages: [`Investigation triggered (backend may be offline): ${e.message}`] });
    } finally {
      setInvestigationLoading(false);
    }
  };

  const triggerSOAR = async (actionType: string) => {
    if (!selectedIncident) return;
    setActionLoading(actionType);
    setSoarLog(prev => [`SOAR: Triggered ${actionType} for incident ${selectedIncident.id}...`, ...prev]);
    try {
      await api.triggerAgentTask(`Trigger response playbook for Incident ${selectedIncident.id}. Action: ${actionType}.`);
      setSoarLog(prev => [`SOAR: ${actionType} execution initiated. Approval request sent.`, ...prev]);
    } catch (e: any) {
      setSoarLog(prev => [`SOAR: ${actionType} triggered (sandbox mock).`, ...prev]);
    } finally {
      setActionLoading(null);
    }
  };

  // Filtered incidents
  const filteredIncidents = incidents.filter(inc => {
    if (filterSeverity !== 'ALL' && inc.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && inc.status !== filterStatus) return false;
    if (searchQuery && !inc.title.toLowerCase().includes(searchQuery.toLowerCase()) && !inc.correlation_key?.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const tabs: { id: DetailTab; label: string; icon: React.ElementType }[] = [
    { id: 'summary', label: 'Summary', icon: Eye },
    { id: 'investigation', label: 'AI Investigation', icon: Brain },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'mitre', label: 'MITRE', icon: Target },
    { id: 'soar', label: 'SOAR', icon: Zap },
  ];

  return (
    <div className="p-6 h-[calc(100vh-4rem)] flex gap-6 overflow-hidden">
      {selectedIncident && <MultiplayerCursor incidentId={selectedIncident.id} />}
      
      {/* Left Panel — Incidents List */}
      <div className="w-[380px] flex-shrink-0 bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-lg flex flex-col h-full">
        {/* Filters */}
        <div className="px-4 py-3 border-b border-slate-800 space-y-2 flex-shrink-0">
          <div className="flex justify-between items-center">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Incidents</h3>
            <span className="text-[10px] bg-slate-800 px-2 py-0.5 rounded-full font-bold text-slate-300">
              {filteredIncidents.length}/{incidents.length}
            </span>
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search incidents..."
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-[11px] focus:outline-none focus:border-blue-500/50 text-slate-200 placeholder:text-slate-600"
            />
          </div>
          <div className="flex gap-2">
            <select 
              value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-[10px] text-slate-300 focus:outline-none"
            >
              <option value="ALL">All Severity</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <select 
              value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-[10px] text-slate-300 focus:outline-none"
            >
              <option value="ALL">All Status</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>

        {/* Incident List */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/50">
          {filteredIncidents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-2">
              <CheckCircle className="w-8 h-8 opacity-40 text-emerald-400" />
              <span className="text-xs">No matching incidents found.</span>
            </div>
          ) : (
            filteredIncidents.map(inc => {
              const active = selectedIncident?.id === inc.id;
              return (
                <div 
                  key={inc.id}
                  onClick={() => handleSelectIncident(inc)}
                  className={`p-4 cursor-pointer hover:bg-slate-800/20 transition-all ${
                    active ? 'bg-blue-950/20 border-l-2 border-blue-500' : 'border-l-2 border-transparent'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-semibold text-slate-200 block truncate max-w-[220px]">{inc.title}</span>
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-md flex-shrink-0 ${
                      inc.severity === 'CRITICAL' 
                        ? 'bg-red-950/40 text-red-400 border border-red-800/30' 
                        : inc.severity === 'HIGH'
                        ? 'bg-orange-950/40 text-orange-400 border border-orange-800/30'
                        : 'bg-amber-950/40 text-amber-400 border border-amber-800/30'
                    }`}>
                      {inc.severity}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1 font-mono truncate">{inc.correlation_key}</p>
                  <div className="flex justify-between items-center mt-2">
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${
                      inc.status === 'RESOLVED' 
                        ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/30' 
                        : 'bg-blue-950/40 text-blue-400 border border-blue-800/30'
                    }`}>
                      {inc.status}
                    </span>
                    <span className="text-[10px] text-slate-600">{new Date(inc.timestamp).toLocaleDateString()}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Right Panel — Detail Workbench */}
      <div className="flex-1 bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-lg flex flex-col h-full">
        {selectedIncident ? (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Header with actions */}
            <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center flex-shrink-0">
              <div className="min-w-0">
                <h2 className="text-sm font-bold text-slate-200 truncate">{selectedIncident.title}</h2>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  ID: <span className="font-mono text-slate-300">#{selectedIncident.id}</span> • 
                  Key: <span className="font-mono text-slate-300">{selectedIncident.correlation_key}</span>
                </p>
              </div>
              <div className="flex gap-2 flex-shrink-0">
                <button
                  onClick={handleRunInvestigation}
                  disabled={investigationLoading}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-3 py-1.5 rounded-lg text-xs transition-all flex items-center gap-1.5 shadow-lg shadow-indigo-900/20"
                >
                  {investigationLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Brain className="w-3 h-3" />}
                  Investigate
                </button>
                <button
                  onClick={() => handleUpdateIncident('RESOLVED', 'TRUE_POSITIVE')}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-3 py-1.5 rounded-lg text-xs transition-all"
                  disabled={updating}
                >
                  TP Resolve
                </button>
                <button
                  onClick={() => handleUpdateIncident('RESOLVED', 'FALSE_POSITIVE')}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-semibold px-3 py-1.5 rounded-lg text-xs transition-all"
                  disabled={updating}
                >
                  FP Dismiss
                </button>
              </div>
            </div>

            {/* Tab Navigation */}
            <div className="px-6 border-b border-slate-800 flex gap-1 flex-shrink-0">
              {tabs.map(tab => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-1.5 px-3 py-2.5 text-[10px] font-bold uppercase tracking-wider transition-all border-b-2 ${
                      active 
                        ? 'text-blue-400 border-blue-500' 
                        : 'text-slate-500 border-transparent hover:text-slate-300'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5">
              
              {/* SUMMARY TAB */}
              {activeTab === 'summary' && (
                <>
                  {/* AI Summary */}
                  <div className="bg-gradient-to-r from-slate-950 to-indigo-950/20 border border-indigo-900/20 rounded-xl p-5 relative overflow-hidden">
                    <div className="flex items-center gap-2 mb-3">
                      <Sparkles className="w-4 h-4 text-indigo-400" />
                      <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">AI Investigation Summary</h4>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {selectedIncident.llm_summary || "No AI analysis available yet. Click 'Investigate' to trigger the multi-agent investigation pipeline."}
                    </p>
                  </div>

                  {/* Incident Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      { label: 'Severity', value: selectedIncident.severity, color: selectedIncident.severity === 'CRITICAL' ? 'text-red-400' : 'text-amber-400' },
                      { label: 'Status', value: selectedIncident.status, color: selectedIncident.status === 'RESOLVED' ? 'text-emerald-400' : 'text-blue-400' },
                      { label: 'Verdict', value: selectedIncident.verdict || 'PENDING', color: 'text-slate-300' },
                      { label: 'Created', value: new Date(selectedIncident.timestamp).toLocaleString(), color: 'text-slate-300' },
                    ].map((item, idx) => (
                      <div key={idx} className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                        <p className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">{item.label}</p>
                        <p className={`text-xs font-bold mt-1 ${item.color}`}>{item.value}</p>
                      </div>
                    ))}
                  </div>

                  {/* Related Alerts */}
                  {incidentDetails?.alerts && incidentDetails.alerts.length > 0 && (
                    <div>
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-500" /> Correlated Alerts ({incidentDetails.alerts.length})
                      </h4>
                      <div className="space-y-2">
                        {incidentDetails.alerts.slice(0, 5).map((alert: any) => (
                          <div key={alert.id} className="bg-slate-950/40 border border-slate-800 rounded-lg p-3 flex justify-between items-center">
                            <div>
                              <span className="text-[10px] font-semibold text-slate-200">{alert.title}</span>
                              <p className="text-[9px] text-slate-500 mt-0.5">
                                {alert.attack_type} • IP: <span className="font-mono">{alert.attacker_ip}</span>
                              </p>
                            </div>
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                              alert.severity === 'CRITICAL' ? 'bg-red-950/40 text-red-400' : 'bg-amber-950/40 text-amber-400'
                            }`}>{alert.severity}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Analyst Notes */}
                  <div className="space-y-2">
                    <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider">Analyst Notes</label>
                    <textarea
                      value={notes}
                      onChange={e => setNotes(e.target.value)}
                      className="w-full bg-slate-950/60 border border-slate-800 rounded-xl px-4 py-3 text-xs focus:outline-none focus:border-blue-500/50 transition-all text-slate-200 h-24 resize-none"
                      placeholder="Enter investigation observations, hypothesis, or findings..."
                    />
                  </div>
                </>
              )}

              {/* INVESTIGATION TAB */}
              {activeTab === 'investigation' && (
                <div className="space-y-4">
                  {investigationLoading ? (
                    <div className="flex flex-col items-center justify-center py-16 gap-3">
                      <Loader2 className="w-8 h-8 text-indigo-400 animate-spin" />
                      <p className="text-xs text-slate-400">Running multi-agent investigation pipeline...</p>
                      <p className="text-[10px] text-slate-600">Planner → Supervisor → Threat Hunter → SOAR → Executive</p>
                    </div>
                  ) : investigation ? (
                    <div className="space-y-3">
                      <div className="bg-indigo-950/20 border border-indigo-800/30 rounded-xl p-4">
                        <h4 className="text-xs font-bold text-indigo-300 mb-2">Agent Team Results</h4>
                        {investigation.messages?.map((msg: string, idx: number) => (
                          <div key={idx} className="text-[11px] text-slate-300 py-1.5 border-b border-slate-800/50 last:border-0 flex items-start gap-2">
                            <ChevronRight className="w-3 h-3 text-indigo-400 mt-0.5 flex-shrink-0" />
                            <span>{msg}</span>
                          </div>
                        ))}
                      </div>

                      {/* XAI Panel Integration */}
                      {investigation.xai_payload && (
                        <div className="mt-4">
                          <XAIPanel xaiData={investigation.xai_payload} />
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-16 text-slate-500 gap-3">
                      <Brain className="w-10 h-10 opacity-30" />
                      <p className="text-xs">Click "Investigate" to run the multi-agent pipeline</p>
                    </div>
                  )}
                </div>
              )}

              {/* TIMELINE TAB */}
              {activeTab === 'timeline' && (
                <div className="space-y-4">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Event Timeline</h4>
                  {incidentDetails?.related_logs && incidentDetails.related_logs.length > 0 ? (
                    <div className="relative pl-6 border-l-2 border-slate-800 space-y-4">
                      {incidentDetails.related_logs.slice(0, 20).map((log: any, idx: number) => (
                        <div key={idx} className="relative">
                          <div className="absolute -left-[25px] top-1 w-3 h-3 rounded-full bg-slate-800 border-2 border-blue-500"></div>
                          <div className="bg-slate-950/40 border border-slate-800 rounded-lg p-3">
                            <div className="flex justify-between items-center mb-1">
                              <span className="text-[10px] font-bold text-slate-300">{log.event_type || 'Log Event'}</span>
                              <span className="text-[9px] text-slate-500 font-mono">{new Date(log.timestamp).toLocaleString()}</span>
                            </div>
                            <p className="text-[10px] text-slate-400">
                              IP: <span className="font-mono text-slate-300">{log.source_ip}</span>
                              {log.endpoint && <> • Endpoint: <span className="font-mono text-slate-300">{log.endpoint}</span></>}
                              {log.user_id && <> • User: <span className="text-slate-300">{log.user_id}</span></>}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex items-center justify-center py-12 text-slate-500 text-xs gap-2">
                      <Clock className="w-5 h-5 opacity-30" /> No timeline data available
                    </div>
                  )}
                </div>
              )}

              {/* MITRE TAB */}
              {activeTab === 'mitre' && (
                <div className="space-y-4">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-violet-400" /> MITRE ATT&CK Mapping
                  </h4>
                  {incidentDetails?.alerts?.map((alert: any) => {
                    const mitre = alert.mitre_mapping || {};
                    return (
                      <div key={alert.id} className="bg-slate-950/40 border border-slate-800 rounded-xl p-4 space-y-3">
                        <p className="text-xs font-semibold text-slate-200">Alert: {alert.attack_type}</p>
                        <div className="grid grid-cols-2 gap-2">
                          {mitre.techniques?.map((tech: any, idx: number) => (
                            <div key={idx} className="bg-violet-950/20 border border-violet-800/30 rounded-lg p-2.5">
                              <p className="text-[10px] font-bold text-violet-300">{tech.technique_id}</p>
                              <p className="text-[9px] text-slate-400">{tech.technique_name}</p>
                            </div>
                          )) || (
                            <p className="text-[10px] text-slate-500 col-span-2">MITRE mapping will populate after investigation</p>
                          )}
                        </div>
                      </div>
                    );
                  }) || (
                    <div className="flex items-center justify-center py-12 text-slate-500 text-xs gap-2">
                      <Target className="w-5 h-5 opacity-30" /> Run investigation to generate MITRE mappings
                    </div>
                  )}
                </div>
              )}

              {/* SOAR TAB */}
              {activeTab === 'soar' && (
                <div className="space-y-5">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Zap className="w-4 h-4 text-blue-500" /> Containment Playbooks
                  </h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      { action: 'IP_BLOCK', label: 'Block Source IP', icon: Lock, hoverColor: 'hover:border-red-800/40 hover:bg-red-950/10' },
                      { action: 'HOST_ISOLATE', label: 'Isolate Host', icon: Shield, hoverColor: 'hover:border-red-800/40 hover:bg-red-950/10' },
                      { action: 'USER_DISABLE', label: 'Disable User', icon: UserX, hoverColor: 'hover:border-red-800/40 hover:bg-red-950/10' },
                      { action: 'JIRA_TICKET', label: 'Create Ticket', icon: FileSpreadsheet, hoverColor: 'hover:border-blue-800/40 hover:bg-blue-950/10' },
                    ].map(btn => {
                      const Icon = btn.icon;
                      return (
                        <button
                          key={btn.action}
                          onClick={() => triggerSOAR(btn.action)}
                          disabled={actionLoading !== null}
                          className={`bg-slate-950 border border-slate-800 ${btn.hoverColor} p-4 rounded-xl text-center group transition-all text-xs font-semibold`}
                        >
                          <Icon className="w-5 h-5 mx-auto mb-2 text-slate-400 group-hover:text-slate-200 transition-all" />
                          {actionLoading === btn.action ? 'Executing...' : btn.label}
                        </button>
                      );
                    })}
                  </div>

                  {/* Natural Language SOAR */}
                  <VoiceCommandBar />

                  {/* Execution Log */}
                  {soarLog.length > 0 && (
                    <div className="space-y-2">
                      <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider">Execution Feed</label>
                      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-[10px] text-slate-300 space-y-1.5 h-40 overflow-y-auto">
                        {soarLog.map((log, idx) => (
                          <div key={idx} className="truncate">
                            <span className="text-blue-500">[{new Date().toLocaleTimeString()}]</span> {log}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-500 gap-3">
            <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center">
              <AlertTriangle className="w-8 h-8 opacity-30 text-blue-500" />
            </div>
            <span className="text-xs">Select an incident to begin triage workbench</span>
            <span className="text-[10px] text-slate-600">Use filters and search to narrow down incidents</span>
          </div>
        )}
      </div>
    </div>
  );
}
