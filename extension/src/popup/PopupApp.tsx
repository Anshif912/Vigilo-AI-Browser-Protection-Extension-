import React, { useEffect, useState } from 'react';
import { ShieldCheck, Power, Globe } from 'lucide-react';
import { getSettings, updateSettings, ActivityLog } from '../services/storage';
import { useLanguage } from '../i18n';
import { LanguageSelector } from '../components/LanguageSelector';
import { ThreatStoryCard } from '../components/ThreatStoryCard';

export const PopupApp: React.FC = () => {
  const { t } = useLanguage();
  const [isEnabled, setIsEnabled] = useState(true);
  const [, setThreatsBlocked] = useState(0);
  const [, setLastThreat] = useState<string | null>(null);
  const [recentActivity, setRecentActivity] = useState<ActivityLog[]>([]);
  const [currentWebsite, setCurrentWebsite] = useState<string>('github.com');
  const [activeUrl, setActiveUrl] = useState<string>('');
  const [currentStatus, setCurrentStatus] = useState<string>('Safe');
  const [analysis, setAnalysis] = useState<any>(null);

  useEffect(() => {
    getSettings().then((settings) => {
      setIsEnabled(settings.protectionEnabled);
      setThreatsBlocked(settings.threatsBlockedCount);
      setLastThreat(settings.lastThreat);
      setRecentActivity(settings.recentActivity);
    });

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['currentWebsite', 'currentStatus', 'currentAnalysis'], (res) => {
        if (res.currentWebsite) setCurrentWebsite(res.currentWebsite);
        if (res.currentStatus) setCurrentStatus(res.currentStatus);
        if (res.currentAnalysis) setAnalysis(res.currentAnalysis);
      });

      if (chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]?.url) {
            const rawUrl = tabs[0].url;
            setActiveUrl(rawUrl);
            try {
              const url = new URL(rawUrl);
              if (url.hostname && !url.hostname.includes('chrome')) {
                setCurrentWebsite(url.hostname);
              }
            } catch {
              // ignore internal tab URLs
            }
          }
        });
      }
    }
  }, []);

  const toggleProtection = async () => {
    const nextState = !isEnabled;
    setIsEnabled(nextState);
    await updateSettings({ protectionEnabled: nextState });
  };

  const isHttpUrl = activeUrl ? activeUrl.toLowerCase().startsWith('http://') : false;

  let isAnalysisCurrent = false;
  if (analysis && analysis.url && currentWebsite) {
    try {
      const analysisHost = new URL(analysis.url).hostname.toLowerCase();
      const currentHost = currentWebsite.toLowerCase();
      isAnalysisCurrent = analysisHost === currentHost || analysisHost.includes(currentHost) || currentHost.includes(analysisHost);
    } catch {
      isAnalysisCurrent = false;
    }
  }

  const effectiveTechnical = (isAnalysisCurrent && analysis?.technical_status)
    ? analysis.technical_status
    : 'Reachable';

  const effectiveProtocol = (isAnalysisCurrent && analysis?.transport_protocol)
    ? analysis.transport_protocol
    : (isHttpUrl ? 'HTTP' : 'HTTPS');

  const effectiveSecurity = (isAnalysisCurrent && analysis?.connection_security)
    ? analysis.connection_security
    : (isHttpUrl ? 'Not Secure' : 'Secure');

  const effectiveStatus = (isAnalysisCurrent && (analysis?.overall_status || analysis?.status))
    ? (analysis?.overall_status || analysis?.status)
    : (isHttpUrl ? 'Suspicious' : currentStatus);

  const displayAnalysis = isAnalysisCurrent ? analysis : null;

  return (
    <div className="w-[360px] bg-[#0B1220] text-slate-100 p-5 font-sans min-h-[460px] flex flex-col justify-between select-none relative overflow-visible">
      {/* Header */}
      <div>
        <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 z-50 relative overflow-visible">
          <div className="flex items-center space-x-2">
            <div className="relative">
              <div className="w-8 h-8 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-blue-500" />
              </div>
              {isEnabled && (
                <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-500 rounded-full ring-2 ring-[#0B1220] animate-pulse" />
              )}
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-1">
                {t('app.title')}
                <span className="text-[10px] uppercase tracking-wider font-semibold px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  v4.0 OS
                </span>
              </h1>
              <p className="text-[11px] text-slate-400">{t('app.subtitle')}</p>
            </div>
          </div>

          <div className="flex items-center space-x-1.5">
            <LanguageSelector />
            <button
              onClick={toggleProtection}
              className={`flex items-center space-x-1 px-2.5 py-1 rounded-full border text-[11px] font-semibold transition-all duration-300 ${
                isEnabled
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20'
              }`}
            >
              <Power className="w-3 h-3" />
              <span>{isEnabled ? t('app.active') : t('app.off')}</span>
            </button>
          </div>
        </div>

        {/* Protection Status Banner */}
        <div className="mt-3 p-3 rounded-2xl glass-card border border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Globe className="w-4 h-4 text-slate-400" />
              <div>
                <span className="text-[10px] font-medium text-slate-400 uppercase tracking-wider block">
                  Current Website
                </span>
                <span className="text-xs font-semibold text-slate-200 truncate max-w-[130px] block">
                  {currentWebsite}
                </span>
              </div>
            </div>
            <div className="text-right flex items-center gap-1.5">
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                  effectiveSecurity.includes('Not Secure') || effectiveSecurity.includes('Invalid') || effectiveSecurity.includes('Unable')
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}
              >
                {effectiveProtocol} ({effectiveSecurity})
              </span>
              <span
                className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border ${
                  effectiveStatus === 'Critical' || effectiveStatus === 'High Risk'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    : effectiveStatus === 'Suspicious'
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    : effectiveStatus === 'Unverified'
                    ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                    : effectiveStatus === 'Low Risk'
                    ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}
              >
                {effectiveStatus}
              </span>
            </div>
          </div>

          {/* 4-Signal Multi-Status Telemetry */}
          <div className="pt-2 border-t border-slate-800/60 grid grid-cols-2 gap-2 text-[10px]">
            <div>
              <span className="text-slate-500 block uppercase">Technical Status</span>
              <span className={`font-semibold truncate block ${effectiveTechnical.includes('Unreachable') || effectiveTechnical.includes('DNS') ? 'text-amber-400' : 'text-slate-300'}`}>
                {effectiveTechnical}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Threat Score & Confidence</span>
              <span className={`font-mono font-bold block ${displayAnalysis && displayAnalysis.threat_score >= 60 ? 'text-rose-400' : displayAnalysis && displayAnalysis.threat_score >= 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {displayAnalysis ? `${displayAnalysis.threat_score}/100 (${displayAnalysis.confidence || 85}% ${displayAnalysis.confidence_level || 'High'})` : 'N/A (Unverified)'}
              </span>
            </div>
          </div>
        </div>

        {/* AI Threat Story Card */}
        {displayAnalysis && (
          <div className="mt-3">
            <ThreatStoryCard analysis={displayAnalysis} />
          </div>
        )}

        {/* Recent Activity */}
        <div className="mt-4">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2">
            {t('app.recentActivity')}
          </span>
          <div className="space-y-1.5">
            {recentActivity.slice(0, 3).map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2 rounded-xl bg-slate-900/60 border border-slate-800/60 text-xs"
              >
                <span className="text-slate-300 font-mono truncate max-w-[180px]">
                  {item.domain}
                </span>
                <span
                  className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                    item.status === 'blocked'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  }`}
                >
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="pt-3 border-t border-slate-800/80 text-center text-[10px] text-slate-500">
        Vigilo v4.0 Multi-Signal Engine • Enterprise Threat OS
      </div>
    </div>
  );
};
