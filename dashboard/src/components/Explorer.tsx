import React, { useState, useEffect, useRef } from 'react';
import { Flame, FolderGit2, Search, Filter, Activity, SearchX } from 'lucide-react';
import { motion } from 'framer-motion';
import type { ThreatSummary, CampaignSummary } from '../services/api';

interface ExplorerProps {
  threats: ThreatSummary[];
  campaigns: CampaignSummary[];
  selectedThreatId: string | null;
  selectedCampaignId: string | null;
  onSelectThreat: (id: string) => void;
  onSelectCampaign: (id: string | null) => void;
  onClearSelection: () => void;
}

export const Explorer: React.FC<ExplorerProps> = ({
  threats,
  campaigns,
  selectedThreatId,
  selectedCampaignId,
  onSelectThreat,
  onSelectCampaign,
  onClearSelection
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'Critical' | 'Suspicious'>('ALL');
  const [keyboardIndex, setKeyboardIndex] = useState<number>(0);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const selectedItemRef = useRef<HTMLButtonElement>(null);

  // Filter threats
  const filteredThreats = threats.filter(t => {
    const matchesSearch = t.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          t.website_identity.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || t.status === statusFilter;
    const matchesCampaign = !selectedCampaignId || t.campaign_id === selectedCampaignId;
    return matchesSearch && matchesStatus && matchesCampaign;
  });

  // Sync keyboardIndex when selectedThreatId changes
  useEffect(() => {
    if (selectedThreatId) {
      const idx = filteredThreats.findIndex(t => t.id === selectedThreatId);
      if (idx !== -1) setKeyboardIndex(idx);
    }
  }, [selectedThreatId, filteredThreats]);

  // Auto-scroll selected row into view
  useEffect(() => {
    if (selectedItemRef.current) {
      selectedItemRef.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [keyboardIndex]);

  // Keyboard Accessibility (Global Shortcuts)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+K or Cmd+K -> Focus Search
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (searchInputRef.current) {
          searchInputRef.current.focus();
          searchInputRef.current.select();
        }
        return;
      }

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setKeyboardIndex(prev => {
          const next = Math.min(prev + 1, filteredThreats.length - 1);
          if (filteredThreats[next]) {
            onSelectThreat(filteredThreats[next].id);
          }
          return next;
        });
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setKeyboardIndex(prev => {
          const next = Math.max(prev - 1, 0);
          if (filteredThreats[next]) {
            onSelectThreat(filteredThreats[next].id);
          }
          return next;
        });
      } else if (e.key === 'Enter') {
        if (filteredThreats[keyboardIndex]) {
          onSelectThreat(filteredThreats[keyboardIndex].id);
        }
      } else if (e.key === 'Escape') {
        onClearSelection();
        if (searchInputRef.current) searchInputRef.current.blur();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [filteredThreats, keyboardIndex, onSelectThreat, onClearSelection]);

  return (
    <aside className="w-80 border-r border-slate-800 bg-slate-950/60 flex flex-col h-[calc(100vh-4rem)] overflow-hidden">
      {/* Search & Filter Bar */}
      <div className="p-3 border-b border-slate-800 space-y-2 bg-slate-900/40">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search domain, brand... (Ctrl+K)"
            aria-label="Search Threat Queue"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-md text-xs text-slate-200 focus-ring transition-all placeholder:text-slate-500"
          />
        </div>

        <div className="flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span>Filter:</span>
          </div>
          <div className="flex gap-1">
            {(['ALL', 'Critical', 'Suspicious'] as const).map(status => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                aria-label={`Filter by ${status}`}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors focus-ring ${
                  statusFilter === status
                    ? 'bg-blue-600/30 text-blue-400 border border-blue-500/40'
                    : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-slate-900">
        {/* 🔥 Priority Threat Queue */}
        <div className="p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200 uppercase tracking-wider">
              <Flame className="w-4 h-4 text-rose-500" />
              <span>Priority Threat Queue</span>
            </div>
            <span className="text-[11px] font-semibold text-slate-500 px-1.5 py-0.5 rounded bg-slate-900">
              {filteredThreats.length}
            </span>
          </div>

          <div className="space-y-1.5">
            {filteredThreats.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800 text-center space-y-1">
                <SearchX className="w-6 h-6 text-slate-500 mx-auto" />
                <p className="text-xs font-semibold text-slate-300">No Matching Threats</p>
                <p className="text-[11px] text-slate-500">Try another keyword, domain, or fingerprint.</p>
              </div>
            ) : (
              filteredThreats.map((threat, idx) => {
                const isSelected = threat.id === selectedThreatId;
                const isFocused = idx === keyboardIndex;
                const isCritical = threat.status === 'Critical';
                return (
                  <motion.button
                    key={threat.id}
                    ref={isSelected ? selectedItemRef : null}
                    onClick={() => {
                      setKeyboardIndex(idx);
                      onSelectThreat(threat.id);
                    }}
                    whileHover={{ scale: 1.01, x: 2 }}
                    whileTap={{ scale: 0.99 }}
                    transition={{ duration: 0.18 }}
                    aria-label={`Threat ${threat.domain}, status ${threat.status}, score ${threat.threat_score}`}
                    className={`w-full text-left p-2.5 rounded-lg border transition-all relative focus-ring ${
                      isSelected
                        ? 'bg-blue-950/50 border-blue-500/80 shadow-lg shadow-blue-500/10 ring-1 ring-blue-500/40'
                        : isFocused
                        ? 'bg-slate-900 border-slate-700 ring-1 ring-slate-600'
                        : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-slate-200 truncate max-w-[170px]" title={threat.domain}>
                        {threat.domain}
                      </span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                        isCritical
                          ? 'bg-rose-950/80 text-rose-400 border border-rose-800/60'
                          : 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                      }`}>
                        {threat.status}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="text-slate-400">{threat.website_identity}</span>
                      <span className="font-mono font-bold text-slate-300">Score: {threat.threat_score}</span>
                    </div>
                  </motion.button>
                );
              })
            )}
          </div>
        </div>

        {/* 📁 Active Campaigns Queue */}
        <div className="p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200 uppercase tracking-wider">
              <FolderGit2 className="w-4 h-4 text-purple-400" />
              <span>Active Campaigns</span>
            </div>
            {selectedCampaignId && (
              <button
                onClick={() => onSelectCampaign(null)}
                className="text-[10px] text-blue-400 hover:underline"
              >
                Clear Filter
              </button>
            )}
          </div>

          <div className="space-y-1.5">
            {campaigns.map(camp => {
              const isSelected = camp.id === selectedCampaignId;
              return (
                <motion.button
                  key={camp.id}
                  onClick={() => onSelectCampaign(isSelected ? null : camp.id)}
                  whileHover={{ scale: 1.01, x: 2 }}
                  transition={{ duration: 0.18 }}
                  aria-label={`Campaign ${camp.name}, target ${camp.target_brand}`}
                  className={`w-full text-left p-2 rounded-lg border transition-all focus-ring ${
                    isSelected
                      ? 'bg-purple-950/40 border-purple-500/60'
                      : 'bg-slate-900/30 border-slate-800/60 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-300 truncate max-w-[180px]">
                      {camp.name}
                    </span>
                    <span className="text-[10px] font-semibold text-purple-300 bg-purple-950/60 border border-purple-800/60 px-1.5 py-0.2 rounded">
                      {camp.total_occurrences} Threat{camp.total_occurrences > 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span>Target: {camp.target_brand}</span>
                    <span className="text-rose-400 font-semibold">{camp.threat_level}</span>
                  </div>
                </motion.button>
              );
            })}
          </div>
        </div>

        {/* ⚡ Live Operational Activity Feed */}
        <div className="p-3 bg-slate-950/40">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200 uppercase tracking-wider">
              <Activity className="w-4 h-4 text-emerald-400 animate-pulse" />
              <span>Live Activity Feed</span>
            </div>
          </div>
          <div className="space-y-1.5 text-[11px] font-mono">
            {threats.slice(0, 3).map((t, idx) => (
              <div key={idx} className="p-2 rounded bg-slate-900/60 border border-slate-800/80 text-slate-300">
                <div className="flex justify-between text-[10px] text-slate-500 mb-0.5">
                  <span className="text-emerald-400 font-bold">THREAT ENRICHED</span>
                  <span>Just now</span>
                </div>
                <div className="truncate text-slate-200 font-semibold">{t.domain}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </aside>
  );
};
