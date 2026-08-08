import { fetchUrlAnalysis, AnalysisResponse } from './api';
import { getSettings, recordThreatBlocked, recordActivity } from './storage';

export type DecisionType = 'ALLOW' | 'WARNING' | 'BLOCK';

interface DuplicateCacheEntry {
  url: string;
  timestamp: number;
}

class AnalysisService {
  private lastAnalyzed: DuplicateCacheEntry | null = null;
  private bypassedUrls: Set<string> = new Set();

  /**
   * Module 2 — Navigation Guard: Validates supported web URLs
   */
  public isValidWebUrl(url: string): boolean {
    if (!url) return false;
    const lower = url.toLowerCase();

    // Ignore extension pages and custom blocked/warning routes to prevent loops
    if (
      lower.includes('blocked.html') ||
      lower.includes('warning.html') ||
      lower.startsWith('chrome://') ||
      lower.startsWith('edge://') ||
      lower.startsWith('chrome-extension://') ||
      lower.startsWith('about:') ||
      lower.startsWith('file://') ||
      lower.startsWith('view-source:') ||
      lower.startsWith('devtools://') ||
      lower.includes('localhost:8000') ||
      lower.includes('127.0.0.1')
    ) {
      return false;
    }

    // Must start with http:// or https://
    return lower.startsWith('http://') || lower.startsWith('https://');
  }

  /**
   * Module 3 — Duplicate Request Protection
   */
  private isDuplicateRequest(url: string): boolean {
    const now = Date.now();
    if (
      this.lastAnalyzed &&
      this.lastAnalyzed.url === url &&
      now - this.lastAnalyzed.timestamp < 2000
    ) {
      return true;
    }
    this.lastAnalyzed = { url, timestamp: now };
    return false;
  }

  /**
   * Module 6 — Decision Engine (Single Source of Truth)
   */
  public evaluateThreat(score: number, status?: string): DecisionType {
    if (status === 'Critical' || status === 'High Risk' || status === 'Unverified' || score >= 60) return 'BLOCK';
    if (status === 'Suspicious' || score >= 40) return 'WARNING';
    return 'ALLOW';
  }

  /**
   * User bypass for "Continue with Caution"
   */
  public allowBypass(url: string) {
    this.bypassedUrls.add(url);
  }

  /**
   * Handle DOM Interstitial Warning Inspection
   */
  public async handleDomInspection(tabId: number, url: string, domTitle: string, domText: string): Promise<void> {
    if (!this.isValidWebUrl(url)) return;
    if (this.bypassedUrls.has(url)) return;

    const analysis = await fetchUrlAnalysis(url, domTitle, domText);
    if (!analysis) return;

    let domain = 'website';
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url;
    }

    await chrome.storage.local.set({
      currentWebsite: domain,
      currentStatus: analysis.status,
      currentThreatScore: analysis.threat_score,
      currentAnalysis: analysis
    });

    const decision = this.evaluateThreat(analysis.threat_score, analysis.status);

    if (decision === 'BLOCK') {
      await recordThreatBlocked(analysis.website_identity, domain);

      const params = new URLSearchParams({
        url: url,
        score: analysis.threat_score.toString(),
        identity: analysis.website_identity,
        attack_type: analysis.attack_type,
        category: analysis.category || 'Browser Security Warning',
        sub_category: analysis.sub_category || 'Upstream Security Interstitial',
        confidence: (analysis.confidence || 98).toString(),
        confidence_level: analysis.confidence_level || 'High',
        reason: analysis.reason,
        risk_reasoning_summary: analysis.risk_reasoning_summary || analysis.reason,
        at_risk: JSON.stringify(analysis.information_at_risk),
        why: JSON.stringify(analysis.why_blocked),
        recommended: analysis.recommended_action,
        analysis_id: analysis.analysis_id,
        score_breakdown: JSON.stringify(analysis.score_breakdown || []),
        structured_evidence: JSON.stringify(analysis.structured_evidence || {}),
        ioc: JSON.stringify(analysis.ioc || {}),
        analysis_trace: JSON.stringify(analysis.analysis_trace || []),
        ai_explanation: JSON.stringify(analysis.ai_explanation || {}),
        threat_timeline: JSON.stringify(analysis.threat_timeline || [])
      });

      const redirectUrl = chrome.runtime.getURL(`blocked.html?${params.toString()}`);
      chrome.tabs.update(tabId, { url: redirectUrl });
    }
  }

  /**
   * Main Navigation Interception Handler
   */
  public async handleNavigation(tabId: number, url: string): Promise<void> {
    if (!this.isValidWebUrl(url)) return;

    if (this.bypassedUrls.has(url)) {
      return;
    }

    if (this.isDuplicateRequest(url)) {
      return;
    }

    const settings = await getSettings();
    if (!settings.protectionEnabled) return;

    let domain = 'website';
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url;
    }

    // Module 4 — Backend Communication with Timeout & Graceful Error Handling
    const analysis: AnalysisResponse | null = await fetchUrlAnalysis(url);

    // Module 13 — Error Handling: Backend offline/timeout -> Graceful Fallback
    if (!analysis) {
      const isHttp = url.toLowerCase().startsWith('http://');
      await chrome.storage.local.set({
        currentWebsite: domain,
        currentStatus: isHttp ? 'Suspicious' : 'Safe',
        currentThreatScore: isHttp ? 35 : 0
      });
      return;
    }

    // Save active tab state for Popup
    await chrome.storage.local.set({
      currentWebsite: domain,
      currentStatus: analysis.status,
      currentThreatScore: analysis.threat_score,
      currentAnalysis: analysis
    });

    const decision = this.evaluateThreat(analysis.threat_score, analysis.status);

    if (decision === 'BLOCK') {
      // Module 9 — Attack Prevented Flow
      await recordThreatBlocked(analysis.website_identity, domain);

      const params = new URLSearchParams({
        url: url,
        score: analysis.threat_score.toString(),
        identity: analysis.website_identity,
        attack_type: analysis.attack_type,
        category: analysis.category || 'Credential Phishing',
        sub_category: analysis.sub_category || 'Subdomain Impersonation',
        confidence: (analysis.confidence || 85).toString(),
        confidence_level: analysis.confidence_level || 'High',
        reason: analysis.reason,
        risk_reasoning_summary: analysis.risk_reasoning_summary || analysis.reason,
        at_risk: JSON.stringify(analysis.information_at_risk),
        why: JSON.stringify(analysis.why_blocked),
        recommended: analysis.recommended_action,
        analysis_id: analysis.analysis_id,
        score_breakdown: JSON.stringify(analysis.score_breakdown || []),
        structured_evidence: JSON.stringify(analysis.structured_evidence || {}),
        ioc: JSON.stringify(analysis.ioc || {}),
        analysis_trace: JSON.stringify(analysis.analysis_trace || []),
        ai_explanation: JSON.stringify(analysis.ai_explanation || {}),
        threat_timeline: JSON.stringify(analysis.threat_timeline || []),
        status: analysis.status || ''
      });

      const redirectUrl = chrome.runtime.getURL(`blocked.html?${params.toString()}`);
      chrome.tabs.update(tabId, { url: redirectUrl });
    } else if (decision === 'WARNING') {
      // Module 8 — Warning Flow
      await recordActivity(domain, 'suspicious');

      // Send on-page toast alert to tab
      chrome.tabs.sendMessage(tabId, {
        type: 'VIGILO_NOTIFICATION',
        title: '⚠ Suspicious Website Detected',
        text: `${analysis.website_identity} (Threat Score: ${analysis.threat_score}/100)`,
        style: 'suspicious'
      }).catch(() => {});

      const params = new URLSearchParams({
        url: url,
        score: analysis.threat_score.toString(),
        identity: analysis.website_identity,
        attack_type: analysis.attack_type,
        category: analysis.category || 'Credential Phishing',
        sub_category: analysis.sub_category || 'Subdomain Impersonation',
        confidence: (analysis.confidence || 85).toString(),
        confidence_level: analysis.confidence_level || 'High',
        reason: analysis.reason,
        risk_reasoning_summary: analysis.risk_reasoning_summary || analysis.reason,
        analysis_id: analysis.analysis_id,
        ai_explanation: JSON.stringify(analysis.ai_explanation || {}),
        threat_timeline: JSON.stringify(analysis.threat_timeline || [])
      });

      const redirectUrl = chrome.runtime.getURL(`warning.html?${params.toString()}`);
      chrome.tabs.update(tabId, { url: redirectUrl });
    } else {
      // Module 7 — Safe / Low Risk Navigation
      await recordActivity(domain, 'safe');

      const isHttp = analysis.transport_protocol === 'HTTP' || analysis.connection_security === 'Not Secure';
      
      if (isHttp) {
        chrome.tabs.sendMessage(tabId, {
          type: 'VIGILO_NOTIFICATION',
          title: '⚠ Connection is Not Secure',
          text: 'HTTP connection detected (No encryption)',
          style: 'not_secure'
        }).catch(() => {});
      } else {
        chrome.tabs.sendMessage(tabId, {
          type: 'VIGILO_NOTIFICATION',
          title: '✓ Website Analyzed',
          text: 'No threat indicators detected',
          style: 'safe'
        }).catch(() => {});
      }
    }
  }
}

export const analysisService = new AnalysisService();
