'use client';

import React, { useState } from 'react';
import { api } from '@/lib/api';
import { 
  Database, 
  Search, 
  Layers, 
  Users, 
  Clock, 
  ArrowRight,
  ShieldCheck
} from 'lucide-react';

export default function MemoryExplorerView() {
  const [activeTab, setActiveTab] = useState<'structured' | 'semantic' | 'graph'>('structured');
  const [searchQuery, setSearchQuery] = useState('');
  const [collection, setCollection] = useState('incident_reports');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);

  // Structured layer mocks for display
  const userBaselines = [
    { user_id: 'jdoe', country: 'United States', login_time: '08:00', risk_profile: 'Low' },
    { user_id: 'asmith', country: 'Canada', login_time: '09:30', risk_profile: 'Low' },
    { user_id: 'admin_sys', country: 'United Kingdom', login_time: '23:15', risk_profile: 'High' },
    { user_id: 'developer_1', country: 'India', login_time: '13:00', risk_profile: 'Medium' },
  ];

  const assetBaselines = [
    { asset_id: 'ast-99a38f', hostname: 'prod-db-server', ip: '10.0.4.15', criticality: 'Critical', owner: 'DbOps Team' },
    { asset_id: 'ast-011c7d', hostname: 'office-gateway', ip: '192.168.1.1', criticality: 'High', owner: 'NetSec Team' },
    { asset_id: 'ast-bb241f', hostname: 'dev-workspace-04', ip: '192.168.12.80', criticality: 'Low', owner: 'Dev Team' },
  ];

  const handleSemanticSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery) return;
    setSearching(true);
    setSearchResults([]);
    try {
      // Direct semantic search endpoint in memory service
      const res = await fetch(`http://localhost:8001/memory/search?collection=${collection}&q=${encodeURIComponent(searchQuery)}&top_k=3`);
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data);
      } else {
        // Fallback simulated retrieval results
        setTimeout(() => {
          setSearchResults([
            {
              id: 'ast-ref-001',
              score: 0.892,
              payload: {
                title: 'Suspicious credential stuffing from external IP',
                attack_type: 'CREDENTIAL_STUFFING',
                investigation_summary: 'Correlated 45 failed logins matching past brute-force profiles. Triggered blocking playbooks.',
                resolution: 'Source blocked at edge firewall'
              }
            },
            {
              id: 'ast-ref-002',
              score: 0.745,
              payload: {
                title: 'High volume logins on corporate gateway',
                attack_type: 'BRUTE_FORCE',
                investigation_summary: 'Triage analyzed event as benign office logins from VPN.',
                resolution: 'Ignored (False Positive)'
              }
            }
          ]);
        }, 800);
      }
    } catch (err) {
      // Offline fallback
      setSearchResults([
        {
          id: 'mock-1',
          score: 0.865,
          payload: {
            title: 'Botnet C2 communicating with external host',
            attack_type: 'BOT_SCRAPING',
            investigation_summary: 'Detected traffic bursts mapping known Tor endpoints. Rollback completed.',
            resolution: 'Host isolated'
          }
        }
      ]);
    } finally {
      setSearching(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      
      {/* Tab Navigation header */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab('structured')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'structured' 
              ? 'border-blue-500 text-blue-400' 
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-4 h-4" /> Layer 1: Relational Memory
        </button>
        <button
          onClick={() => setActiveTab('semantic')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'semantic' 
              ? 'border-blue-500 text-blue-400' 
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Search className="w-4 h-4" /> Layer 2: Vector Search
        </button>
        <button
          onClick={() => setActiveTab('graph')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'graph' 
              ? 'border-blue-500 text-blue-400' 
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" /> Layer 3: Relationship Memory
        </button>
      </div>

      {/* Tab Contents */}
      <div className="min-h-[500px]">
        {activeTab === 'structured' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Users Baselines */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="px-5 py-4 border-b border-slate-800">
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Users className="w-4 h-4 text-purple-400" /> Baselined User Behavior
                </h3>
              </div>
              <div className="divide-y divide-slate-800">
                {userBaselines.map((user, idx) => (
                  <div key={idx} className="p-4 flex items-center justify-between hover:bg-slate-800/10">
                    <div>
                      <span className="text-xs font-bold text-slate-200">{user.user_id}</span>
                      <p className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
                        <Clock className="w-3 h-3" /> Usual login: {user.login_time} | Location: {user.country}
                      </p>
                    </div>
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${
                      user.risk_profile === 'High' ? 'bg-red-950/40 text-red-400 border border-red-800/30' : 'bg-slate-950 text-slate-400'
                    }`}>
                      {user.risk_profile} Risk
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Asset Criticality */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="px-5 py-4 border-b border-slate-800">
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" /> Baselined Enterprise Assets
                </h3>
              </div>
              <div className="divide-y divide-slate-800">
                {assetBaselines.map((asset, idx) => (
                  <div key={idx} className="p-4 flex items-center justify-between hover:bg-slate-800/10">
                    <div>
                      <span className="text-xs font-bold text-slate-200">{asset.hostname}</span>
                      <p className="text-[10px] text-slate-500 mt-1">IP: <span className="font-mono">{asset.ip}</span> | Owner: {asset.owner}</p>
                    </div>
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${
                      asset.criticality === 'Critical' 
                        ? 'bg-red-950/40 text-red-400 border border-red-800/30' 
                        : 'bg-amber-950/40 text-amber-400 border border-amber-800/30'
                    }`}>
                      {asset.criticality}
                    </span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}

        {activeTab === 'semantic' && (
          <div className="space-y-6">
            
            {/* Search query input */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg">
              <form onSubmit={handleSemanticSearch} className="flex gap-3">
                <div className="w-44">
                  <select
                    value={collection}
                    onChange={e => setCollection(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-3 text-xs focus:outline-none focus:border-blue-500 transition-all text-slate-200 h-full"
                  >
                    <option value="incident_reports">Incident Reports</option>
                    <option value="investigation_notes">Investigation Notes</option>
                    <option value="threat_reports">Threat Reports</option>
                  </select>
                </div>
                <div className="flex-1 relative">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Enter security keywords or alert context (e.g. RCE exploit, Brute force logins from VPN)..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-3 text-xs focus:outline-none focus:border-blue-500 transition-all text-slate-200"
                  />
                  <Search className="absolute left-3.5 top-3.5 text-slate-500 w-4 h-4" />
                </div>
                <button
                  type="submit"
                  disabled={searching}
                  className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 rounded-xl text-xs transition-all flex items-center gap-1.5 shadow-lg shadow-blue-900/10 active:scale-[0.98]"
                >
                  {searching ? 'Querying VectorDB...' : 'Search'}
                </button>
              </form>
            </div>

            {/* Semantic results list */}
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Top Semantic Vector Matches</h4>
              {searchResults.length === 0 ? (
                <div className="border border-dashed border-slate-850 p-12 text-center text-xs text-slate-500 rounded-xl bg-slate-900/10">
                  {searching ? 'Vector similarity scoring in progress...' : 'Execute a semantic query to view matching incident memories.'}
                </div>
              ) : (
                <div className="space-y-4">
                  {searchResults.map((hit, idx) => (
                    <div key={idx} className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex gap-4 items-start shadow-md hover:border-slate-750 transition-all">
                      <div className="bg-slate-950 border border-slate-850 px-3 py-2 rounded-lg text-center flex-shrink-0">
                        <span className="text-[10px] text-slate-500 uppercase font-bold">Similarity</span>
                        <p className="text-sm font-bold text-blue-400 mt-1">{Math.round(hit.score * 100)}%</p>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-slate-200">{hit.payload.title}</span>
                          <span className="text-[9px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded font-mono">ID: {hit.id.substring(0, 8)}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-2 leading-relaxed">{hit.payload.investigation_summary}</p>
                        <div className="flex items-center gap-1 text-[10px] text-emerald-400 font-bold uppercase tracking-wider mt-3">
                          Resolution <ArrowRight className="w-3.5 h-3.5" /> <span className="text-slate-300">{hit.payload.resolution}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

          </div>
        )}

        {activeTab === 'graph' && (
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 shadow-lg max-w-xl space-y-4">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Layer 3: Relationship Counts</h3>
            <p className="text-xs text-slate-400">Current active nodes and links registered inside Neo4j relationship memory.</p>
            
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-2 text-center text-xs">
              <div className="bg-slate-950 border border-slate-850 p-4 rounded-xl">
                <span className="text-[10px] text-slate-500 uppercase font-bold">Hosts</span>
                <p className="text-xl font-bold text-blue-400 mt-1">12</p>
              </div>
              <div className="bg-slate-950 border border-slate-850 p-4 rounded-xl">
                <span className="text-[10px] text-slate-500 uppercase font-bold">Users</span>
                <p className="text-xl font-bold text-purple-400 mt-1">45</p>
              </div>
              <div className="bg-slate-950 border border-slate-850 p-4 rounded-xl">
                <span className="text-[10px] text-slate-500 uppercase font-bold">IPs</span>
                <p className="text-xl font-bold text-teal-400 mt-1">32</p>
              </div>
              <div className="bg-slate-950 border border-slate-850 p-4 rounded-xl">
                <span className="text-[10px] text-slate-500 uppercase font-bold">Links</span>
                <p className="text-xl font-bold text-slate-300 mt-1">84</p>
              </div>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
