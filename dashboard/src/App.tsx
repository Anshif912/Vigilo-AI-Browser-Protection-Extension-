import { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { Explorer } from './components/Explorer';
import { InvestigationWorkspace } from './components/InvestigationWorkspace';
import { Inspector } from './components/Inspector';
import { EmptyState } from './components/EmptyState';
import { ToastContainer } from './components/ToastContainer';
import type { ToastMessage } from './components/ToastContainer';
import { OfflineBanner } from './components/OfflineBanner';
import {
  fetchStats,
  fetchHealth,
  fetchCampaigns,
  fetchThreats,
  fetchUnifiedInvestigation,
} from './services/api';
import type {
  SystemStats,
  SystemHealth,
  CampaignSummary,
  ThreatSummary,
  InvestigationPayload
} from './services/api';

import { RadarBackground } from './components/RadarBackground';
import { MagicInteractionEngine } from './components/MagicInteractionEngine';

export function App() {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [threats, setThreats] = useState<ThreatSummary[]>([]);

  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);

  const [investigationPayload, setInvestigationPayload] = useState<InvestigationPayload | null>(null);
  const [loadingWorkspace, setLoadingWorkspace] = useState<boolean>(false);

  // LiveOps Synchronization State
  const [isOffline, setIsOffline] = useState<boolean>(false);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [lastSyncedSec, setLastSyncedSec] = useState<number>(0);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const prevThreatCountRef = useRef<number>(0);

  // Toast Helper
  const addToast = (type: 'threat' | 'success' | 'info', title: string, message: string) => {
    const newToast: ToastMessage = {
      id: Math.random().toString(36).substr(2, 9),
      type,
      title,
      message
    };
    setToasts(prev => [newToast, ...prev].slice(0, 4));

    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== newToast.id));
    }, 4500);
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  // 5-Second Intelligent Polling Sync Engine
  const syncPlatformData = async (isManual = false) => {
    if (!isManual) setIsSyncing(true);
    try {
      const [statsRes, healthRes, campRes, threatRes] = await Promise.all([
        fetchStats(),
        fetchHealth(),
        fetchCampaigns(),
        fetchThreats()
      ]);

      setStats(statsRes);
      setHealth(healthRes);
      setCampaigns(campRes);
      setThreats(threatRes);
      setIsOffline(false);
      setLastSyncedSec(0);

      // Check if new threat detected since last sync
      if (prevThreatCountRef.current > 0 && threatRes.length > prevThreatCountRef.current) {
        const newest = threatRes[0];
        addToast(
          'threat',
          `🛡 New Threat Detected [${newest.status}]`,
          `${newest.domain} (${newest.website_identity})`
        );
      }
      prevThreatCountRef.current = threatRes.length;

      // Auto-select first threat on initial boot
      if (threatRes.length > 0 && !selectedThreatId) {
        handleSelectThreat(threatRes[0].id, false);
      }
    } catch (err) {
      console.warn('[Vigilo LiveOps] Backend connection offline:', err);
      setIsOffline(true);
    } finally {
      setIsSyncing(false);
    }
  };

  // Polling Lifecycle & Freshness Counter
  useEffect(() => {
    syncPlatformData(true);

    const pollInterval = setInterval(() => {
      syncPlatformData();
    }, 5000);

    const timerInterval = setInterval(() => {
      setLastSyncedSec(prev => prev + 1);
    }, 1000);

    return () => {
      clearInterval(pollInterval);
      clearInterval(timerInterval);
    };
  }, [selectedThreatId]);

  // Handle Threat Selection
  const handleSelectThreat = async (threatId: string, showLoading = true) => {
    setSelectedThreatId(threatId);
    if (showLoading) setLoadingWorkspace(true);
    try {
      const payload = await fetchUnifiedInvestigation(threatId);
      setInvestigationPayload(payload);
    } catch (err) {
      console.error('Failed to load investigation payload:', err);
    } finally {
      if (showLoading) setLoadingWorkspace(false);
    }
  };

  // Handle Clear Selection (Esc key)
  const handleClearSelection = () => {
    setSelectedThreatId(null);
    setInvestigationPayload(null);
  };

  // Handle Campaign Selection Filter
  const handleSelectCampaign = (campaignId: string | null) => {
    setSelectedCampaignId(campaignId);
    if (campaignId) {
      const matching = threats.find(t => t.campaign_id === campaignId);
      if (matching) {
        handleSelectThreat(matching.id);
      }
    }
  };

  return (
    <MagicInteractionEngine>
      <div className="min-h-screen bg-black text-slate-100 flex flex-col font-sans antialiased relative selection:bg-purple-500/30">
        {/* Full-Screen Animated Radar Background */}
        <RadarBackground />

        {/* Connection Recovery Banner */}
        <OfflineBanner isOffline={isOffline} />

        {/* Global Toast Notification System */}
        <ToastContainer toasts={toasts} onDismiss={removeToast} />

        {/* Global Header */}
        <Header
          stats={stats}
          health={health}
          lastSyncedSec={lastSyncedSec}
          isSyncing={isSyncing}
          onRefresh={() => syncPlatformData(true)}
        />

        {/* Main 3-Panel OS Grid */}
        <div className="flex-1 flex overflow-hidden">
          {/* Left Explorer Panel */}
          <Explorer
            threats={threats}
            campaigns={campaigns}
            selectedThreatId={selectedThreatId}
            selectedCampaignId={selectedCampaignId}
            onSelectThreat={handleSelectThreat}
            onSelectCampaign={handleSelectCampaign}
            onClearSelection={handleClearSelection}
          />

          {/* Center Investigation Workspace Panel */}
          {selectedThreatId ? (
            <InvestigationWorkspace payload={investigationPayload} loading={loadingWorkspace} />
          ) : (
            <EmptyState />
          )}

          {/* Right Inspector Panel */}
          <Inspector
            payload={investigationPayload}
            health={health}
            onToast={addToast}
          />
        </div>
      </div>
    </MagicInteractionEngine>
  );
}

export default App;
