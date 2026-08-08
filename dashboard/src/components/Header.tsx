import React from 'react';
import { Shield, Activity, AlertTriangle, Layers, Server, Command, RefreshCw } from 'lucide-react';
import type { SystemStats, SystemHealth } from '../services/api';
import { LanguageSelector } from './LanguageSelector';

interface HeaderProps {
  stats: SystemStats | null;
  health: SystemHealth | null;
  lastSyncedSec: number;
  isSyncing: boolean;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ stats, health, lastSyncedSec, isSyncing, onRefresh }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
      {/* Product Branding */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-500/10">
          <Shield className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-white">
              Vigilo <span className="text-blue-400 font-semibold text-xs tracking-wider uppercase px-2 py-0.5 rounded bg-blue-950/80 border border-blue-800/60 ml-1">LiveOps</span>
            </h1>
          </div>
          <p className="text-xs text-slate-400">Protect One. Protect Everyone.</p>
        </div>
      </div>

      {/* Keyboard Shortcut Hint Badges */}
      <div className="hidden lg:flex items-center gap-2 text-[11px] font-mono text-slate-400 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800/80">
        <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">↑↓</kbd> Navigate</span>
        <span className="text-slate-600">•</span>
        <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">↵</kbd> Open</span>
        <span className="text-slate-600">•</span>
        <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">Esc</kbd> Clear</span>
        <span className="text-slate-600">•</span>
        <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 flex items-center gap-0.5"><Command className="w-2.5 h-2.5" />K</kbd> Search</span>
      </div>

      {/* Global System Stats & Operational Badges */}
      <div className="flex items-center gap-6">
        {/* Freshness Indicator */}
        <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 bg-slate-900/80 px-2.5 py-1 rounded-md border border-slate-800">
          {isSyncing ? (
            <RefreshCw className="w-3 h-3 text-blue-400 animate-spin" />
          ) : (
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          )}
          <span>Last Synced: {lastSyncedSec}s ago</span>
        </div>

        {/* System Health */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-xs text-slate-400">System:</span>
          <span className="text-xs font-semibold text-emerald-400 capitalize">{health?.status || 'Operational'}</span>
        </div>

        <div className="h-4 w-[1px] bg-slate-800" />

        {/* Stats Metrics */}
        <div className="flex items-center gap-5 text-xs">
          <div className="flex items-center gap-2 text-slate-300">
            <Activity className="w-4 h-4 text-blue-400" />
            <span className="text-slate-400">Threats:</span>
            <span className="font-bold text-white bg-slate-800 px-2 py-0.5 rounded transition-all">{stats?.total_threats ?? 0}</span>
          </div>

          <div className="flex items-center gap-2 text-slate-300">
            <Layers className="w-4 h-4 text-purple-400" />
            <span className="text-slate-400">Campaigns:</span>
            <span className="font-bold text-white bg-slate-800 px-2 py-0.5 rounded transition-all">{stats?.active_campaigns ?? 0}</span>
          </div>

          <div className="flex items-center gap-2 text-slate-300">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span className="text-slate-400">Critical:</span>
            <span className="font-bold text-rose-400 bg-rose-950/60 border border-rose-800/60 px-2 py-0.5 rounded transition-all">{stats?.critical_campaigns ?? 0}</span>
          </div>
        </div>

        <div className="h-4 w-[1px] bg-slate-800" />

        <LanguageSelector />

        <button
          onClick={onRefresh}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800 transition-colors focus-ring"
          title="Manual Refresh"
          aria-label="Manual Refresh System Data"
        >
          <Server className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
