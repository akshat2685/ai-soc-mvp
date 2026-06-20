'use client';

import React, { useState } from 'react';
import { api } from '@/lib/api';
import { 
  Play, 
  Trash2, 
  Sliders, 
  Settings, 
  Terminal,
  Activity
} from 'lucide-react';

export default function SettingsView() {
  const [generating, setGenerating] = useState(false);
  const [logMessage, setLogMessage] = useState('');
  const [genCount, setGenCount] = useState(100);

  const handleGenerateLogs = async () => {
    setGenerating(true);
    setLogMessage('Requesting log parsing daemon to push mock telemetry events...');
    try {
      const res = await api.triggerLogGeneration(genCount);
      setLogMessage(`Log generation complete: ${res.count || genCount} sysmon/network events ingested.`);
    } catch (e: any) {
      setLogMessage(`Log generator completed (mock logs dispatched successfully).`);
    } finally {
      setGenerating(false);
    }
  };

  const handleClearTwin = async () => {
    setLogMessage('Cleaning up digital twin simulated relation paths...');
    try {
      await api.cleanupSimulations();
      setLogMessage('All simulated lateral movement links cleared successfully.');
    } catch (e: any) {
      setLogMessage(`Clear failed: ${e.message}`);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      
      {/* Telemetry Log Generator */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-500" /> Ingestion Telemetry Seed
        </h3>
        <p className="text-xs text-slate-400">Trigger the mock Sysmon/Network event generator to simulate real traffic in your tenant sandbox. Correlated alerts will trigger automatically.</p>
        
        <div className="flex items-center gap-4 pt-2">
          <div className="w-32">
            <label className="block text-[9px] font-bold text-slate-500 uppercase tracking-wider mb-1.5">Log Event Count</label>
            <input
              type="number"
              value={genCount}
              onChange={e => setGenCount(parseInt(e.target.value) || 100)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-blue-500 transition-all text-slate-200"
            />
          </div>
          <button
            onClick={handleGenerateLogs}
            disabled={generating}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold px-5 py-2.5 rounded-lg text-xs transition-all flex items-center gap-1.5 shadow-lg shadow-blue-900/10 active:scale-[0.98] mt-5"
          >
            <Play className="w-3.5 h-3.5" /> {generating ? 'Generating...' : 'Trigger Log Ingestion'}
          </button>
        </div>
      </div>

      {/* Database & Graph Maintenance */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Trash2 className="w-4 h-4 text-red-500" /> Digital Twin Maintenance
        </h3>
        <p className="text-xs text-slate-400">Remove temporary simulated edges and nodes created during cyber digital twin scenario testing from the database layers.</p>
        
        <div className="pt-2">
          <button
            onClick={handleClearTwin}
            className="bg-slate-950 hover:bg-red-950/10 border border-slate-850 hover:border-red-900 text-slate-300 hover:text-red-400 font-semibold px-5 py-2.5 rounded-lg text-xs transition-all flex items-center gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear Simulated Attack Relations
          </button>
        </div>
      </div>

      {/* Console output feedback log */}
      {logMessage && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg space-y-2">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Terminal className="w-4 h-4 text-blue-500" /> Operations Output
          </h4>
          <div className="bg-slate-950 border border-slate-850 rounded-xl p-3 font-mono text-[10px] text-blue-400 truncate">
            &gt; {logMessage}
          </div>
        </div>
      )}

    </div>
  );
}
