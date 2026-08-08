import React from 'react';
import { ShieldAlert, MousePointerClick } from 'lucide-react';

export const EmptyState: React.FC = () => {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-12 text-center bg-slate-950/40">
      <div className="w-16 h-16 rounded-2xl bg-blue-950/60 border border-blue-800/60 flex items-center justify-center text-blue-400 mb-4 shadow-xl shadow-blue-500/5">
        <ShieldAlert className="w-8 h-8 text-blue-400" />
      </div>
      <h3 className="text-xl font-bold text-white mb-2">No Active Investigation Selected</h3>
      <p className="text-xs text-slate-400 max-w-md leading-relaxed mb-6">
        Select a threat from the Priority Threat Queue or Active Campaigns in the Explorer panel to begin reviewing campaign details, evidence, indicators of compromise, and chronological investigation history.
      </p>
      <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 font-medium">
        <MousePointerClick className="w-4 h-4 text-blue-400" />
        <span>Click any threat item on the left to populate case file</span>
      </div>
    </div>
  );
};
