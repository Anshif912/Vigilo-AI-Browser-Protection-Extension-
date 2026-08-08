export interface AnalysisResponse {
  analysis_id: string;
  timestamp: string;
  url: string;
  status: 'Safe' | 'Suspicious' | 'Critical';
  threat_score: number;
  website_identity: string;
  attack_type: string;
  reason: string;
  information_at_risk: string[];
  why_blocked: string[];
  recommended_action: string;
  category?: string;
  sub_category?: string;
  confidence?: number;
  confidence_level?: string;
  overall_status?: string;
  connection_security?: string;
  transport_protocol?: string;
  tls_status?: string;
  security_reason?: string;
  risk_reasoning_summary?: string;
  score_breakdown?: any[];
  structured_evidence?: any;
  ioc?: any;
  analysis_trace?: any[];
  ai_explanation?: any;
  threat_timeline?: any[];
}

const BACKEND_URL = 'http://localhost:8000/api/analyze-url';
const TIMEOUT_MS = 2000; // 2-second strict timeout requirement

export async function fetchUrlAnalysis(
  targetUrl: string,
  domTitle?: string,
  domText?: string
): Promise<AnalysisResponse | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: targetUrl,
        dom_title: domTitle,
        dom_text: domText
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`[Vigilo] API returned status ${response.status} for ${targetUrl}`);
      return null;
    }

    const data: any = await response.json();

    if (
      !data ||
      typeof data.status !== 'string' ||
      typeof data.threat_score !== 'number'
    ) {
      console.warn('[Vigilo] Malformed backend response structure:', data);
      return null;
    }

    return {
      analysis_id: data.analysis_id || 'local-id',
      timestamp: data.timestamp || new Date().toISOString(),
      url: data.url || targetUrl,
      status: (['Safe', 'Suspicious', 'Critical'].includes(data.status) ? data.status : 'Safe') as any,
      threat_score: Math.min(Math.max(data.threat_score, 0), 100),
      website_identity: data.website_identity || targetUrl,
      attack_type: data.attack_type || 'Unknown',
      reason: data.reason || 'Analysis complete',
      information_at_risk: Array.isArray(data.information_at_risk) ? data.information_at_risk : [],
      why_blocked: Array.isArray(data.why_blocked) ? data.why_blocked : [],
      recommended_action: data.recommended_action || 'Proceed with caution.',
      category: data.category,
      sub_category: data.sub_category,
      confidence: data.confidence,
      confidence_level: data.confidence_level,
      overall_status: data.overall_status,
      connection_security: data.connection_security,
      transport_protocol: data.transport_protocol,
      tls_status: data.tls_status,
      security_reason: data.security_reason,
      risk_reasoning_summary: data.risk_reasoning_summary,
      score_breakdown: data.score_breakdown,
      structured_evidence: data.structured_evidence,
      ioc: data.ioc,
      analysis_trace: data.analysis_trace,
      ai_explanation: data.ai_explanation,
      threat_timeline: data.threat_timeline
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      console.warn(`[Vigilo] API request timed out after ${TIMEOUT_MS}ms for URL: ${targetUrl}`);
    } else {
      console.warn('[Vigilo] Network or backend error:', err.message || err);
    }
    return null;
  }
}
