import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, AlertTriangle, ArrowRight, ShieldCheck, Lock } from 'lucide-react';

export const WarningPage: React.FC = () => {
  const [params, setParams] = useState({
    url: 'https://suspicious-website.com',
    score: 65,
    identity: 'Unverified Web Portal',
    reason: 'This website contains deceptive layout features and unverified identity characteristics.'
  });

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const url = searchParams.get('url');
    const score = searchParams.get('score');
    const identity = searchParams.get('identity');
    const reason = searchParams.get('reason');

    if (url) {
      setParams({
        url: url,
        score: score ? parseInt(score, 10) : 65,
        identity: identity || 'Unverified Web Portal',
        reason: reason || 'This website displays suspicious login patterns and unverified identity.'
      });
    }
  }, []);

  const handleContinue = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ action: 'ALLOW_BYPASS', url: params.url }, () => {
        window.location.href = params.url;
      });
    } else {
      window.location.href = params.url;
    }
  };

  return (
    <div className="min-h-screen bg-[#0B1220] text-slate-100 font-sans selection:bg-amber-500/30 selection:text-amber-200 flex flex-col justify-between p-6 sm:p-10 relative overflow-hidden">
      {/* Background Ambient Glows */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-amber-600/15 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute top-1/2 -right-40 w-96 h-96 bg-blue-600/10 rounded-full blur-[140px] pointer-events-none" />

      {/* Header Bar */}
      <div className="max-w-4xl w-full mx-auto flex items-center justify-between z-10">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-2xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center shadow-lg">
            <ShieldCheck className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              Vigilo
              <span className="text-xs uppercase tracking-widest font-semibold px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
                WARNING
              </span>
            </h1>
            <p className="text-xs text-slate-400">AI Browser Protection System</p>
          </div>
        </div>

        <div className="hidden sm:flex items-center space-x-2 text-xs text-slate-400 bg-slate-900/60 border border-slate-800 px-3.5 py-1.5 rounded-full backdrop-blur-md">
          <Lock className="w-3.5 h-3.5 text-amber-400" />
          <span>Suspicious Pattern Detected</span>
        </div>
      </div>

      {/* Main Container */}
      <main className="max-w-2xl w-full mx-auto my-auto z-10 space-y-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center space-y-4"
        >
          {/* Animated Amber Shield */}
          <div className="relative inline-block">
            <div className="w-20 h-20 sm:w-24 sm:h-24 rounded-3xl bg-slate-900/90 border border-amber-500/40 flex items-center justify-center mx-auto shadow-2xl relative">
              <ShieldAlert className="w-10 h-10 sm:w-12 sm:h-12 text-amber-400" />
            </div>
          </div>

          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-sm font-bold tracking-wider uppercase">
              <AlertTriangle className="w-4 h-4" />
              Proceed with Caution
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              This website appears suspicious.
            </h2>
            <p className="text-slate-400 text-sm sm:text-base max-w-lg mx-auto leading-relaxed">
              Vigilo flagged anomalous indicators on this web page. Avoid entering sensitive banking details or passwords.
            </p>
          </div>
        </motion.div>

        {/* URL Box */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="glass-card p-4 rounded-2xl border-amber-500/20 flex items-center justify-between gap-3 text-xs sm:text-sm"
        >
          <span className="text-slate-400 font-medium">Target URL:</span>
          <span className="font-mono text-amber-300 bg-amber-950/40 px-3 py-1.5 rounded-lg border border-amber-500/30 truncate max-w-sm">
            {params.url}
          </span>
        </motion.div>

        {/* AI Explanation Card */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="glass-card p-5 rounded-2xl space-y-3"
        >
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              AI Analysis Breakdown
            </span>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
              Threat Score: {params.score}/100
            </span>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            {params.reason}
          </p>
        </motion.div>

        {/* Action Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-4"
        >
          <button
            onClick={handleContinue}
            className="w-full sm:w-auto px-6 py-3 rounded-2xl bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 font-semibold text-sm transition-all duration-300 flex items-center justify-center space-x-2"
          >
            <span>Continue with Caution</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </motion.div>
      </main>

      {/* Footer */}
      <footer className="max-w-4xl w-full mx-auto text-center pt-6 border-t border-slate-800/60 text-xs text-slate-500 z-10">
        Vigilo Security • Real-Time AI Browser Protection
      </footer>
    </div>
  );
};
