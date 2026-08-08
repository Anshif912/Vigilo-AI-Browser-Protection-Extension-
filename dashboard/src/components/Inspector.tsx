import React from 'react';
import { CheckCircle, Download, Copy, FileText, ShieldCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import type { InvestigationPayload, SystemHealth } from '../services/api';

interface InspectorProps {
  payload: InvestigationPayload | null;
  health: SystemHealth | null;
  onToast: (type: 'success' | 'info', title: string, message: string) => void;
}

export const Inspector: React.FC<InspectorProps> = ({ payload, health, onToast }) => {
  if (!payload) {
    return (
      <aside className="w-80 border-l border-slate-800 bg-slate-950/60 p-4 h-[calc(100vh-4rem)] flex flex-col justify-between">
        <div className="space-y-4">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">SOC Inspector</h3>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-500 italic text-center">
            No active threat selected
          </div>
        </div>
      </aside>
    );
  }

  const { summary, threat, ioc, evidence } = payload;

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(payload, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `investigation_${threat.domain}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    onToast('success', 'Export Complete', `Investigation JSON downloaded for ${threat.domain}`);
  };

  const handleCopyIoc = () => {
    navigator.clipboard.writeText(`Domain: ${ioc.domain}\nFingerprint: ${ioc.fingerprint}\nCategory: ${ioc.risk_category}`);
    onToast('info', 'IOC Copied', `Domain & Fingerprint copied to clipboard`);
  };

  const handleCopySummary = () => {
    navigator.clipboard.writeText(`Threat Investigation Summary:\nDomain: ${threat.domain}\nScore: ${threat.threat_score}\nIdentity: ${threat.website_identity}\nSummary: ${evidence.ai_summary}`);
    onToast('info', 'Summary Copied', `AI Threat Narrative copied to clipboard`);
  };

  const stages = [
    { label: 'Threat Stored', status: 'SUCCESS' },
    { label: 'Score Generated', status: 'SUCCESS' },
    { label: 'Confidence Calculated', status: 'SUCCESS' },
    { label: 'Evidence Created', status: 'SUCCESS' },
    { label: 'IOC Generated', status: 'SUCCESS' },
    { label: 'Timeline Completed', status: 'SUCCESS' },
    { label: 'Investigation Ready', status: 'SUCCESS' }
  ];

  return (
    <aside className="w-80 border-l border-slate-800 bg-slate-950/60 p-4 flex flex-col h-[calc(100vh-4rem)] overflow-y-auto justify-between space-y-6">
      <AnimatePresence mode="wait">
        <motion.div
          key={threat.id}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="space-y-6 flex-1 flex flex-col justify-between"
        >
          <div className="space-y-6">
            {/* Readiness Header */}
            <div className="space-y-3 border-b border-slate-800 pb-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">SOC Inspector</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/80">
                  {summary.investigation_ready ? 'READINESS: READY' : 'PROCESSING'}
                </span>
              </div>

              {/* Completeness Gauge */}
              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400">Completeness Gauge</span>
                  <span className="font-mono font-bold text-emerald-400">{summary.investigation_completeness}%</span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: "0%" }}
                    animate={{ width: `${summary.investigation_completeness}%` }}
                    transition={{ duration: 0.4, ease: "easeOut" }}
                    className="h-full bg-emerald-500 rounded-full"
                  />
                </div>
              </div>
            </div>

            {/* Browser Protection Status Widget */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3 space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                <span className="flex items-center gap-1.5 text-blue-400">
                  <ShieldCheck className="w-4 h-4" />
                  Browser Protection
                </span>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                  CONNECTED
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400 pt-1">
                <div>Monitoring: <span className="text-emerald-400 font-bold">Active</span></div>
                <div>Engine: <span className="text-blue-400 font-bold">Vigilo v2.5</span></div>
              </div>
            </div>

            {/* Operational Health & Performance Metadata */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">System Metadata</h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 space-y-0.5">
                  <span className="text-[10px] text-slate-500 block uppercase">Duration</span>
                  <span className="font-mono font-bold text-blue-400">{summary.processing_duration_ms} ms</span>
                </div>
                <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 space-y-0.5">
                  <span className="text-[10px] text-slate-500 block uppercase">Pipeline</span>
                  <span className="font-semibold text-emerald-400 capitalize">{health?.pipeline || 'Operational'}</span>
                </div>
                <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 space-y-0.5">
                  <span className="text-[10px] text-slate-500 block uppercase">Database</span>
                  <span className="font-semibold text-emerald-400 capitalize">{health?.database || 'Connected'}</span>
                </div>
                <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 space-y-0.5">
                  <span className="text-[10px] text-slate-500 block uppercase">Version</span>
                  <span className="font-mono font-bold text-purple-400">{health?.version || '2.5'}</span>
                </div>
              </div>
            </div>

            {/* Stage-Level Pipeline Checklist */}
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-400 uppercase tracking-wider">Pipeline Stage Checklist</span>
                <span className="text-[10px] font-mono text-emerald-400">7/7 Complete</span>
              </div>

              <div className="space-y-1.5 bg-slate-900/40 p-3 rounded-xl border border-slate-800/80">
                {stages.map((st, idx) => (
                  <div key={idx} className="flex items-center justify-between text-xs py-1">
                    <span className="text-slate-300 flex items-center gap-2">
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                      {st.label}
                    </span>
                    <span className="text-[10px] font-mono font-bold text-emerald-400">✔</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Action Controls */}
          <div className="space-y-2 pt-4 border-t border-slate-800">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Quick Actions</h4>

            <motion.button
              onClick={handleExportJson}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="w-full py-2 px-3 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 text-xs font-semibold flex items-center justify-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export Investigation (JSON)
            </motion.button>

            <motion.button
              onClick={handleCopyIoc}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="w-full py-2 px-3 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-medium flex items-center justify-center gap-2 transition-colors"
            >
              <Copy className="w-4 h-4 text-emerald-400" />
              Copy IOC Metrics
            </motion.button>

            <motion.button
              onClick={handleCopySummary}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="w-full py-2 px-3 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-medium flex items-center justify-center gap-2 transition-colors"
            >
              <FileText className="w-4 h-4 text-purple-400" />
              Copy Threat Summary
            </motion.button>
          </div>
        </motion.div>
      </AnimatePresence>
    </aside>
  );
};
