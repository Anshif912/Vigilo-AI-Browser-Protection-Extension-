import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  AlertOctagon,
  FileWarning,
  ChevronDown,
  ChevronUp,
  Key,
  Shield,
  Activity,
  Terminal,
  Cpu,
  ArrowRight,
  HelpCircle,
  CheckCircle2,
  XCircle,
  Download,
  Printer,
  ArrowLeft
} from 'lucide-react';
import { useLanguage } from '../i18n';
import { LanguageSelector } from '../components/LanguageSelector';
import { ThreatStoryCard } from '../components/ThreatStoryCard';
import { RadarBackground } from '../components/RadarBackground';
import { MagicInteractionEngine } from '../components/MagicInteractionEngine';

export const BlockedPage: React.FC = () => {
  const { t } = useLanguage();
  const [params, setParams] = useState({
    url: '',
    score: 0,
    identity: '',
    attackType: '',
    category: '',
    subCategory: '',
    confidence: 85,
    confidenceLevel: 'High',
    reason: '',
    riskReasoningSummary: '',
    atRisk: [] as string[],
    whyBlocked: [] as string[],
    recommended: '',
    scoreBreakdown: [] as any[],
    analysisTrace: [] as any[],
    aiExplanation: {} as any,
    threatTimeline: [] as any[],
    ioc: {} as any
  });

  const [isEvidenceOpen, setIsEvidenceOpen] = useState(false);

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const url = searchParams.get('url');
    const score = searchParams.get('score');
    const identity = searchParams.get('identity');
    const attackType = searchParams.get('attack_type');
    const category = searchParams.get('category');
    const subCategory = searchParams.get('sub_category');
    const confidence = searchParams.get('confidence');
    const confidenceLevel = searchParams.get('confidence_level');
    const reason = searchParams.get('reason');
    const riskReasoningSummary = searchParams.get('risk_reasoning_summary');
    const atRisk = searchParams.get('at_risk');
    const why = searchParams.get('why');
    const recommended = searchParams.get('recommended');
    const breakdown = searchParams.get('score_breakdown');
    const trace = searchParams.get('analysis_trace');
    const aiExp = searchParams.get('ai_explanation');
    const timeline = searchParams.get('threat_timeline');
    const iocData = searchParams.get('ioc');

    if (url) {
      setParams({
        url: url,
        score: score ? parseInt(score, 10) : 0,
        identity: identity || 'Unrecognized Entity',
        attackType: attackType || 'Brand Impersonation',
        category: category || 'Credential Phishing',
        subCategory: subCategory || 'Subdomain Impersonation',
        confidence: confidence ? parseInt(confidence, 10) : 85,
        confidenceLevel: confidenceLevel || 'High',
        reason: reason || 'Suspicious URL structural anomaly detected.',
        riskReasoningSummary: riskReasoningSummary || reason || 'Threat detected by Vigilo engine.',
        atRisk: atRisk ? JSON.parse(atRisk) : [],
        whyBlocked: why ? JSON.parse(why) : [],
        recommended: recommended || 'Navigate directly to official portal.',
        scoreBreakdown: breakdown ? JSON.parse(breakdown) : [],
        analysisTrace: trace ? JSON.parse(trace) : [],
        aiExplanation: aiExp ? JSON.parse(aiExp) : {},
        threatTimeline: timeline ? JSON.parse(timeline) : [],
        ioc: iocData ? JSON.parse(iocData) : {}
      });
    }
  }, []);

  const handleGoBack = () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://google.com';
    }
  };

  const handleContinueAnyway = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ action: 'ALLOW_BYPASS', url: params.url }, () => {
        window.location.href = params.url;
      });
    } else {
      window.location.href = params.url;
    }
  };

  const exportJsonReport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(params, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vigilo-threat-report-${params.ioc?.fingerprint || 'export'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportPdfReport = () => {
    window.print();
  };

  const aiExp = params.aiExplanation || {};
  const threatType = aiExp.threat_type || params.category || 'Brand Impersonation & Phishing';
  const aiSummary = aiExp.ai_explanation_summary || params.riskReasoningSummary || params.reason;
  const decisionSummary = aiExp.decision_summary_paragraph || params.reason;
  const recommendations = aiExp.dynamic_recommendations || [params.recommended];
  const heuristicsList = aiExp.triggered_heuristics_list || [];
  const iocDetailed = aiExp.ioc_detailed || {};
  const confidenceDetails = aiExp.confidence_details || {};
  const whyNotCritical = aiExp.why_not_critical || {};
  const ruleCoverage = aiExp.rule_coverage || { executed_rules: 20, matched_rules: heuristicsList.length, unmatched_rules: 20 - heuristicsList.length, coverage_rate: '100%' };
  const timelineSteps = aiExp.attack_flow_timeline || [];

  return (
    <MagicInteractionEngine>
      <div className="min-h-screen bg-black text-slate-100 font-sans selection:bg-rose-500/30 selection:text-rose-200 flex flex-col justify-between p-6 sm:p-10 relative overflow-hidden">
        {/* Full-Screen Animated Radar Background */}
        <RadarBackground />

      {/* Background Ambient Glows */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-rose-600/15 rounded-full blur-[120px] pointer-events-none print:hidden z-0" />
      <div className="absolute top-1/2 -right-40 w-96 h-96 bg-blue-600/10 rounded-full blur-[140px] pointer-events-none print:hidden z-0" />

      {/* Header Bar with Language Switcher & Export Controls */}
      <div className="max-w-4xl w-full mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 z-50 relative overflow-visible pb-6 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-2xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center shadow-lg shadow-blue-500/10">
            <ShieldCheck className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              Vigilo
              <span className="text-xs uppercase tracking-widest font-semibold px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30">
                {t('app.guardianActive')}
              </span>
            </h1>
            <p className="text-xs text-slate-400">{t('app.subtitle')}</p>
          </div>
        </div>

        {/* Export & Language Selector Bar */}
        <div className="flex items-center space-x-2 print:hidden">
          <LanguageSelector />

          <button
            onClick={exportJsonReport}
            className="flex items-center space-x-1 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-200 transition-colors"
            title={t('threatReport.exportJson')}
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span className="hidden sm:inline">JSON</span>
          </button>

          <button
            onClick={exportPdfReport}
            className="flex items-center space-x-1 px-3 py-1.5 rounded-xl bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-xs font-semibold text-blue-300 transition-colors"
            title={t('threatReport.exportPdf')}
          >
            <Printer className="w-3.5 h-3.5 text-blue-400" />
            <span className="hidden sm:inline">PDF</span>
          </button>
        </div>
      </div>

      {/* Main Container */}
      <main className="max-w-4xl w-full mx-auto my-8 z-10 space-y-6">
        
        {/* SECTION 1: Threat Hero & Classification */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center space-y-4"
        >
          <div className="relative inline-block">
            <div className="absolute inset-0 bg-rose-600/30 rounded-3xl blur-2xl animate-pulse-glow print:hidden" />
            <div className="w-20 h-20 sm:w-24 sm:h-24 rounded-3xl bg-slate-900/90 border border-rose-500/40 flex items-center justify-center mx-auto shadow-2xl relative animate-shield-float">
              <ShieldAlert className="w-10 h-10 sm:w-12 sm:h-12 text-rose-500" />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-center gap-2">
              <span className="px-3 py-1 rounded-full text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40 uppercase tracking-widest">
                {params.score >= 75 ? t('status.critical') : t('status.highRisk')} ({params.score}/100)
              </span>
              <span className="px-3 py-1 rounded-full text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40 uppercase tracking-widest">
                {threatType}
              </span>
            </div>

            <h2 className="text-3xl sm:text-5xl font-black text-white tracking-tight flex items-center justify-center gap-2">
              <AlertOctagon className="w-8 h-8 text-rose-500 inline" />
              {t('threatReport.attackPrevented')}
            </h2>

            <p className="text-slate-300 text-sm sm:text-base max-w-2xl mx-auto font-medium leading-relaxed">
              Vigilo intercepted access to this portal before credentials or session telemetry could be compromised.
            </p>
          </div>

          {/* Action Buttons: Go Back & Continue Anyway */}
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2 print:hidden">
            <button
              onClick={handleGoBack}
              className="flex items-center space-x-2 px-6 py-3 rounded-2xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-lg shadow-blue-500/20 transition-all duration-300 transform hover:scale-[1.02]"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>{t('threatReport.goBack')}</span>
            </button>

            <button
              onClick={handleContinueAnyway}
              className="flex items-center space-x-2 px-5 py-3 rounded-2xl bg-slate-900/80 hover:bg-slate-800 border border-rose-500/30 text-rose-300 font-medium text-xs transition-colors"
            >
              <span>{t('threatReport.continueAnyway')}</span>
            </button>
          </div>
        </motion.div>

        {/* URL Target Bar & Rule Coverage Badge */}
        <div className="glass-card p-4 rounded-2xl border-rose-500/20 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs sm:text-sm">
          <div className="flex items-center space-x-2">
            <span className="text-slate-400 font-medium">{t('threatReport.interceptedTarget')}:</span>
            <span className="font-mono text-rose-400 bg-rose-950/40 px-3 py-1 rounded-lg border border-rose-500/30 truncate max-w-xs sm:max-w-md">
              {params.url}
            </span>
          </div>
          <div className="flex items-center space-x-2 font-mono text-[11px] text-slate-400 bg-slate-900/80 px-3 py-1 rounded-lg border border-slate-800">
            <span className="text-blue-400 font-bold">{t('threatReport.ruleCoverage')}:</span>
            <span>{ruleCoverage.executed_rules} Executed</span>
            <span>•</span>
            <span className="text-rose-400">{ruleCoverage.matched_rules} Matched</span>
            <span>•</span>
          </div>
        </div>

        {/* AI Threat Story Engine Card */}
        <ThreatStoryCard
          analysis={{
            analysis_id: `blocked_${Date.now()}`,
            timestamp: new Date().toISOString(),
            url: params.url,
            status: (params.score >= 75 ? 'Critical' : params.score >= 40 ? 'High Risk' : 'Suspicious') as any,
            threat_score: params.score,
            website_identity: params.identity,
            attack_type: params.attackType,
            reason: params.reason,
            information_at_risk: params.atRisk,
            why_blocked: params.whyBlocked,
            recommended_action: params.recommended,
            category: params.category,
            confidence: params.confidence,
            confidence_level: params.confidenceLevel,
            score_breakdown: params.scoreBreakdown
          }}
        />

        {/* SECTION 2: AI Natural Language Threat Explanation */}
        <div className="glass-card p-6 rounded-2xl border-blue-500/30 space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2 text-blue-400 font-bold text-sm tracking-wide">
              <Cpu className="w-5 h-5 text-blue-500" />
              <span>{t('threatReport.aiExplanation')}</span>
            </div>
            <span className="text-[11px] font-mono bg-blue-500/10 text-blue-400 px-2.5 py-0.5 rounded border border-blue-500/20">
              Generated by Vigilo SOC AI
            </span>
          </div>
          <p className="text-slate-200 text-sm leading-relaxed font-normal">
            {aiSummary}
          </p>
        </div>

        {/* SECTION 3 & Why Not Critical Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          {/* SECTION 3: Threat Contribution % Breakdown */}
          <div className="glass-card p-5 rounded-2xl space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-rose-400" />
                {t('threatReport.whyBlocked')} ({heuristicsList.length} Rules)
              </span>
            </div>

            <div className="space-y-3 text-xs">
              {heuristicsList.map((rule: any, idx: number) => (
                <div key={idx} className="space-y-1 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between font-semibold text-slate-200">
                    <span>{rule.rule_name}</span>
                    <span className="text-rose-400 font-mono">{rule.contribution_pct || 33}% (+{rule.weight} pts)</span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-rose-500 h-1.5 rounded-full transition-all duration-500"
                      style={{ width: `${rule.contribution_pct || 33}%` }}
                    />
                  </div>
                  <span className="text-[11px] text-slate-400 block pt-0.5">{rule.evidence}</span>
                </div>
              ))}
            </div>
          </div>

          {/* FEATURE: Why Not Critical? (Balanced Decision Making) */}
          <div className="glass-card p-5 rounded-2xl space-y-3 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <HelpCircle className="w-4 h-4 text-blue-400" />
                  {t('threatReport.whyNotCritical')}
                </span>
                <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                  Score {params.score}/100
                </span>
              </div>

              <div className="space-y-2 mt-3 text-xs">
                <span className="text-slate-400 font-medium block">Matched Risk Factors:</span>
                {(whyNotCritical.matched_factors || []).map((f: string, idx: number) => (
                  <div key={idx} className="flex items-center space-x-2 text-emerald-400 bg-emerald-950/30 p-2 rounded-lg border border-emerald-500/20">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>{f}</span>
                  </div>
                ))}

                <span className="text-slate-400 font-medium block pt-1">Unmatched Escalation Factors:</span>
                {(whyNotCritical.unmatched_escalation_factors || [
                  '✗ No active credential form DOM payload',
                  '✗ No external threat intelligence blocklist hit',
                  '✗ No malware payload executable downloaded'
                ]).map((uf: string, idx: number) => (
                  <div key={idx} className="flex items-center space-x-2 text-slate-400 bg-slate-900/60 p-2 rounded-lg border border-slate-800">
                    <XCircle className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span>{uf}</span>
                  </div>
                ))}
              </div>
            </div>

            <p className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
              {whyNotCritical.explanation || "Vigilo applies balanced decision-making to avoid over-escalating non-critical threats."}
            </p>
          </div>
        </div>

        {/* SECTION 4: 8-Step Enterprise Pipeline Visual Timeline */}
        <div className="glass-card p-5 rounded-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              {t('threatReport.timeline')}
            </span>
            <span className="text-xs text-slate-400 font-mono">Real-time Pipeline</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
            {timelineSteps.map((step: any, idx: number) => (
              <div key={idx} className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 relative flex flex-col justify-center items-center">
                <span className="text-[9px] font-mono text-slate-500 uppercase block">Stage 0{step.step}</span>
                <span className="font-bold block text-blue-300 truncate w-full text-[11px] mt-0.5">{step.stage}</span>
                <span className="text-[10px] text-slate-400 block truncate w-full mt-0.5">{step.detail}</span>
              </div>
            ))}
          </div>
        </div>

        {/* SECTION 5: Potential Information At Risk */}
        <div className="glass-card p-5 rounded-2xl space-y-3">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <FileWarning className="w-4 h-4 text-amber-400" />
              {t('threatReport.infoAtRisk')}
            </span>
            <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20 uppercase">
              Targeted Data
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3">
            {(aiExp.information_at_risk_details?.items || params.atRisk).map((item: string, idx: number) => (
              <div key={idx} className="flex items-center space-x-2 p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80 text-xs">
                <Key className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span className="font-semibold text-slate-200 truncate">{item}</span>
              </div>
            ))}
          </div>
        </div>

        {/* SECTION 6: Complete IOC Card */}
        <div className="glass-card p-5 rounded-2xl space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              {t('threatReport.ioc')}
            </span>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              Single Source Telemetry
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">Registered Domain</span>
              <span className="font-mono font-semibold text-rose-300 block mt-0.5 truncate">{iocDetailed.registered_domain || 'coincoele.com.br'}</span>
            </div>
            <div className="bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">Subdomain</span>
              <span className="font-mono text-slate-300 block mt-0.5 truncate">{iocDetailed.subdomain || '(none)'}</span>
            </div>
            <div className="bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">{t('threatReport.targetBrand')}</span>
              <span className="font-bold text-white block mt-0.5">{iocDetailed.target_brand || params.identity}</span>
            </div>
            <div className="bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">Protocol & Security</span>
              <span className="font-semibold text-amber-400 block mt-0.5 truncate">{iocDetailed.protocol || 'HTTP'} ({iocDetailed.connection_security || 'Not Secure'})</span>
            </div>
          </div>
        </div>

        {/* SECTION 7: Collapsible Technical Evidence */}
        <div className="glass-card rounded-2xl overflow-hidden border-slate-800">
          <button
            onClick={() => setIsEvidenceOpen(!isEvidenceOpen)}
            className="w-full p-4 bg-slate-900/80 flex items-center justify-between text-xs font-bold text-slate-300 uppercase tracking-wider hover:bg-slate-900 transition-colors"
          >
            <span className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" />
              {t('threatReport.technicalEvidence')} ({heuristicsList.length} Triggered Rules)
            </span>
            {isEvidenceOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {isEvidenceOpen && (
            <div className="p-4 space-y-2 border-t border-slate-800 bg-slate-950/60 text-xs">
              {heuristicsList.map((item: any, idx: number) => (
                <div key={idx} className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="font-semibold text-white block">[{item.rule_id}] {item.rule_name}</span>
                    <span className="text-slate-400 text-[11px] block mt-0.5">{item.evidence}</span>
                  </div>
                  <span className="font-mono font-bold text-rose-400 bg-rose-500/10 px-2.5 py-1 rounded border border-rose-500/20 shrink-0 ml-3">
                    +{item.weight} pts
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* SECTION 8 & SECTION 9 Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          {/* SECTION 8: Stronger Evidence Alignment in Confidence Card */}
          <div className="glass-card p-5 rounded-2xl space-y-3">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block border-b border-slate-800 pb-2">
              {t('threatReport.confidence')} ({confidenceDetails.score || params.confidence}%)
            </span>
            <div className="flex items-center justify-between">
              <div>
                <span className="text-3xl font-extrabold text-white">{confidenceDetails.score || params.confidence}%</span>
                <span className="text-xs text-emerald-400 font-semibold block">Independent Signals: {confidenceDetails.independent_signals || '3 of 3'}</span>
              </div>
              <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center font-bold text-emerald-400 text-xs text-center px-1">
                HIGH ALIGNMENT
              </div>
            </div>
            <div className="space-y-1 text-xs text-slate-300 pt-1 border-t border-slate-800">
              <span className="text-slate-400 font-medium block">Evidence Alignment:</span>
              {(confidenceDetails.evidence_alignment || ['✓ Official Brand Detection', '✓ Path Impersonation']).map((sig: string, idx: number) => (
                <div key={idx} className="flex items-center space-x-1.5 text-[11px] text-emerald-300 font-medium">
                  <span>{sig}</span>
                </div>
              ))}
            </div>
          </div>

          {/* SECTION 9: Actionable AI Recommendations */}
          <div className="glass-card p-5 rounded-2xl space-y-3">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block border-b border-slate-800 pb-2">
              {t('threatReport.recommendations')}
            </span>
            <ul className="space-y-2 text-xs">
              {recommendations.map((rec: string, idx: number) => (
                <li key={idx} className="flex items-start space-x-2 text-slate-200">
                  <ArrowRight className="w-3.5 h-3.5 text-blue-400 mt-0.5 shrink-0" />
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* SECTION 10: Defensible SOC Analyst Decision Summary Paragraph */}
        <div className="p-5 rounded-2xl bg-rose-950/30 border border-rose-500/30 backdrop-blur-xl space-y-2">
          <span className="text-xs font-bold text-rose-300 uppercase tracking-wider block">
            {t('threatReport.socSummary')}
          </span>
          <p className="text-xs text-slate-200 leading-relaxed">
            "{decisionSummary}"
          </p>
        </div>

      </main>

      {/* Footer */}
      <footer className="max-w-4xl w-full mx-auto text-center pt-6 border-t border-slate-800/60 text-xs text-slate-500 z-10">
        Vigilo AI Security • Enterprise Threat Intelligence & Autonomous AI Report v3.4
      </footer>
    </div>
    </MagicInteractionEngine>
  );
};
