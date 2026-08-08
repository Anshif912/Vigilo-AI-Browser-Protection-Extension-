import React from 'react';
import { ShieldAlert, AlertOctagon, Clock, Globe, Fingerprint, Tag, Zap, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';
import type { InvestigationPayload } from '../services/api';
import { SkeletonLoader } from './SkeletonLoader';

interface WorkspaceProps {
  payload: InvestigationPayload | null;
  loading: boolean;
}

export const InvestigationWorkspace: React.FC<WorkspaceProps> = ({ payload, loading }) => {
  if (loading) {
    return <SkeletonLoader />;
  }

  if (!payload) return null;

  const { summary, threat, campaign, score_breakdown, confidence, timeline, ioc, tags, evidence } = payload;
  const isCritical = threat.status === 'Critical';

  return (
    <main className="flex-1 p-6 overflow-y-auto bg-slate-950/40 space-y-6 flex flex-col justify-between">
      <div className="space-y-6">
        {/* 1. Hero Investigation Summary Banner */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, ease: "easeOut" }}
          className={`p-6 rounded-2xl border backdrop-blur-xl relative overflow-hidden shadow-2xl ${
            isCritical
              ? 'bg-rose-950/20 border-rose-500/40 shadow-rose-950/20'
              : 'bg-amber-950/20 border-amber-500/40 shadow-amber-950/20'
          }`}
        >
          <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
            <ShieldAlert className="w-64 h-64 text-rose-500" />
          </div>

          <div className="relative z-10 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-2.5 py-1 rounded-md text-xs font-black uppercase tracking-wider ${
                    isCritical ? 'bg-rose-500 text-slate-950 font-extrabold' : 'bg-amber-500 text-slate-950 font-extrabold'
                  }`}>
                    {summary.risk_level} THREAT DETECTED
                  </span>
                  <span className="text-xs font-mono text-slate-400">ID: {threat.id.slice(0, 8)}</span>
                </div>
                <h2 className="text-2xl font-black tracking-tight text-white">{campaign?.name || threat.website_identity}</h2>
                <p className="text-sm font-mono text-blue-400 mt-1 flex items-center gap-1.5">
                  <Globe className="w-4 h-4" />
                  {threat.url}
                </p>
              </div>

              <div className="text-right flex flex-col items-end">
                <span className="text-xs uppercase text-slate-400 font-semibold tracking-wider">Threat Score</span>
                <span className={`text-4xl font-black font-mono ${isCritical ? 'text-rose-400' : 'text-amber-400'}`}>
                  {threat.threat_score}<span className="text-base text-slate-500 font-normal">/100</span>
                </span>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 pt-4 border-t border-slate-800/80 text-xs">
              <div>
                <span className="text-slate-400 block text-[11px]">Target Brand</span>
                <span className="font-bold text-slate-100 text-sm">{threat.website_identity}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Attack Purpose</span>
                <span className="font-bold text-slate-100 text-sm">{threat.attack_type}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Campaign Confidence</span>
                <span className="font-bold text-emerald-400 text-sm">{confidence.score}%</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Recommended Action</span>
                <span className="font-bold text-rose-400 text-sm uppercase">BLOCK IMMEDIATELY</span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* 2. Threat Analysis & Dynamic Factor Breakdown */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.05, ease: "easeOut" }}
          className="glass-panel p-5 rounded-xl space-y-4"
        >
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200 border-b border-slate-800 pb-3">
            <Zap className="w-4 h-4 text-blue-400" />
            <h3>Threat Analysis & Score Explanation</h3>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-800">
            {evidence.ai_summary}
          </p>

          <div className="space-y-2 pt-2">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Dynamic Score Factors Breakdown</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(Array.isArray(score_breakdown) ? score_breakdown : (score_breakdown?.breakdown || [])).map((item: any, idx: number) => (
                <div key={idx} className="bg-slate-900/80 p-3 rounded-lg border border-slate-800 space-y-1.5">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-300 font-bold">{item.factor}</span>
                    <span className="font-mono font-bold text-blue-400">+{item.weight || item.score} pts</span>
                  </div>
                  {item.evidence && (
                    <p className="text-[11px] text-slate-400 font-sans leading-tight">{item.evidence}</p>
                  )}
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: "0%" }}
                      animate={{ width: `${Math.min(((item.weight || item.score) / 35) * 100, 100)}%` }}
                      transition={{ duration: 0.4, delay: 0.1 + idx * 0.05, ease: "easeOut" }}
                      className="h-full bg-blue-500 rounded-full"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* 3. AI Investigation Narrative & Digital Evidence */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.1, ease: "easeOut" }}
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
        >
          {/* Why Blocked */}
          <div className="glass-panel p-5 rounded-xl space-y-3">
            <div className="flex items-center gap-2 text-xs font-bold text-rose-400 uppercase tracking-wider">
              <AlertOctagon className="w-4 h-4" />
              <h4>Why Blocked Reasons</h4>
            </div>
            <ul className="space-y-2 text-xs">
              {evidence.why_blocked.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2 text-slate-300 bg-rose-950/20 border border-rose-900/40 p-2.5 rounded-lg">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500 mt-1.5 flex-shrink-0" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Information at Risk */}
          <div className="glass-panel p-5 rounded-xl space-y-3">
            <div className="flex items-center gap-2 text-xs font-bold text-amber-400 uppercase tracking-wider">
              <ShieldAlert className="w-4 h-4" />
              <h4>Information at Risk</h4>
            </div>
            <div className="flex flex-wrap gap-2">
              {evidence.information_at_risk.map((info, idx) => (
                <span key={idx} className="px-3 py-1.5 rounded-lg bg-amber-950/40 border border-amber-800/60 text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-400" />
                  {info}
                </span>
              ))}
            </div>
          </div>
        </motion.div>

        {/* 4. Sequential Vertical Chronological Timeline */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.15, ease: "easeOut" }}
          className="glass-panel p-5 rounded-xl space-y-4"
        >
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200 border-b border-slate-800 pb-3">
            <Clock className="w-4 h-4 text-purple-400" />
            <h3>Chronological SOC Investigation Timeline</h3>
          </div>

          <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {timeline.map((event, idx) => {
              const isCrit = event.severity === 'CRITICAL';
              const isSucc = event.severity === 'SUCCESS';
              const isWarn = event.severity === 'WARNING';
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.2, delay: 0.15 + idx * 0.05 }}
                  className="relative group"
                >
                  {/* Node dot */}
                  <div className={`absolute -left-6 top-1 w-3 h-3 rounded-full border-2 ${
                    isCrit ? 'bg-rose-500 border-rose-950' :
                    isSucc ? 'bg-emerald-500 border-emerald-950' :
                    isWarn ? 'bg-amber-500 border-amber-950' : 'bg-blue-500 border-blue-950'
                  }`} />

                  <div className="bg-slate-900/70 p-3 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{event.event_type}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          Actor: {event.actor}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-500">{event.created_at}</span>
                    </div>
                    <p className="text-xs text-slate-400">{event.description}</p>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>

        {/* 5. Detection Trace (Reasoning Sequence) */}
        {payload.analysis_trace && payload.analysis_trace.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, delay: 0.18, ease: "easeOut" }}
            className="glass-panel p-5 rounded-xl space-y-4"
          >
            <div className="flex items-center gap-2 text-sm font-bold text-slate-200 border-b border-slate-800 pb-3">
              <Zap className="w-4 h-4 text-amber-400" />
              <h3>Analysis Reasoning Trace Sequence</h3>
            </div>
            <div className="space-y-2 font-mono text-xs">
              {payload.analysis_trace.map((tr: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-200">[{tr.stage}]</span>
                    <span className="text-slate-400">{tr.result}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    tr.status === 'MATCH' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                    tr.status === 'PASS' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tr.status}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* 6. Indicators of Compromise (IOC) Matrix */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.2, ease: "easeOut" }}
          className="glass-panel p-5 rounded-xl space-y-4"
        >
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200 border-b border-slate-800 pb-3">
            <Fingerprint className="w-4 h-4 text-emerald-400" />
            <h3>Indicators of Compromise (IOC)</h3>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="p-2.5 rounded-l-md">Indicator Domain</th>
                  <th className="p-2.5">TLD</th>
                  <th className="p-2.5">Fingerprint</th>
                  <th className="p-2.5">Risk Category</th>
                  <th className="p-2.5 rounded-r-md">Matching Terms</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                <tr>
                  <td className="p-2.5 font-bold text-blue-400">{ioc.domain}</td>
                  <td className="p-2.5 text-slate-300">.{ioc.tld}</td>
                  <td className="p-2.5 text-emerald-400">{ioc.fingerprint}</td>
                  <td className="p-2.5 text-rose-400 font-sans font-semibold">{ioc.risk_category}</td>
                  <td className="p-2.5 text-slate-400 font-sans">
                    {ioc.keywords.join(', ') || 'N/A'}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* 6. Threat Classification & Categorized Confidence Tags */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.25, ease: "easeOut" }}
          className="glass-panel p-5 rounded-xl space-y-3"
        >
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
            <Tag className="w-4 h-4 text-blue-400" />
            <h4>Threat Classification & Confidence Tags</h4>
          </div>
          <div className="flex flex-wrap gap-2">
            {tags.tags.map((t, idx) => (
              <div key={idx} className="px-3 py-1.5 rounded-lg bg-blue-950/40 border border-blue-800/60 text-xs font-medium text-blue-300 flex items-center gap-2">
                <span>{t.tag}</span>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-blue-900/80 text-blue-200">
                  {t.confidence}%
                </span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* 7. End-to-End Platform Workflow Banner */}
      <div className="mt-8 p-3 rounded-xl bg-slate-900/80 border border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
        <span className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">Vigilo End-to-End Workflow:</span>
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-blue-400">Browser Protection</span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-purple-400">Threat Detection</span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-amber-400">Intelligence Correlation</span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-emerald-400">Enrichment Pipeline</span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-white font-bold bg-blue-600/30 border border-blue-500/40 px-2 py-0.5 rounded">LiveOps Synchronized</span>
        </div>
      </div>
    </main>
  );
};
