const API_BASE = 'http://localhost:8000';

export interface SystemStats {
  total_threats: number;
  active_campaigns: number;
  critical_campaigns: number;
  last_detection: string;
}

export interface SystemHealth {
  status: string;
  database: string;
  pipeline: string;
  version: string;
}

export interface CampaignSummary {
  id: string;
  name: string;
  target_brand: string;
  attack_type: string;
  status: string;
  state: string;
  threat_level: string;
  total_occurrences: number;
  first_seen: string;
  last_seen: string;
  related_urls: string[];
}

export interface ThreatSummary {
  id: string;
  analysis_id: string;
  campaign_id: string;
  campaign_name: string;
  timestamp: string;
  url: string;
  domain: string;
  status: string;
  threat_score: number;
  website_identity: string;
  attack_type: string;
  reason: string;
  campaign_confidence: number;
  investigation_ready: boolean;
  investigation_completeness: number;
  processing_status: string;
}

export interface ScoreFactor {
  factor: string;
  score: number;
}

export interface ConfidenceFactor {
  factor: string;
  weight: number;
}

export interface TimelineEvent {
  id: string;
  event_type: string;
  description: string;
  severity: 'INFO' | 'SUCCESS' | 'WARNING' | 'CRITICAL';
  actor: 'SYSTEM' | 'AI' | 'USER';
  created_at: string;
}

export interface IOCData {
  domain: string;
  tld: string;
  domain_length: number;
  website_identity: string;
  attack_type: string;
  keywords: string[];
  contains_brand: boolean;
  contains_login_terms: boolean;
  contains_banking_terms: boolean;
  risk_category: string;
  fingerprint: string;
}

export interface TagConfidence {
  tag: string;
  confidence: number;
}

export interface TagsData {
  risk_category: string;
  tags: TagConfidence[];
}

export interface EvidenceData {
  reason: string;
  ai_summary: string;
  why_blocked: string[];
  information_at_risk: string[];
  screenshot_path: string | null;
  html_snapshot: string | null;
}

export interface InvestigationPayload {
  summary: {
    risk_level: string;
    campaign_name: string;
    campaign_confidence: number;
    processing_status: string;
    investigation_ready: boolean;
    investigation_completeness: number;
    processing_duration_ms: number;
  };
  threat: {
    id: string;
    analysis_id: string;
    url: string;
    domain: string;
    status: string;
    threat_score: number;
    website_identity: string;
    attack_type: string;
    browser: string;
    pipeline_stages: { stage: string; status: string }[];
    pipeline_version: number;
    schema_version: number;
    timestamp: string;
  };
  campaign: {
    id: string;
    name: string;
    target_brand: string;
    attack_type: string;
    status: string;
    state: string;
    occurrences: number;
  } | null;
  score_breakdown: {
    score: number;
    breakdown: ScoreFactor[];
  };
  confidence: {
    score: number;
    factors: ConfidenceFactor[];
  };
  timeline: TimelineEvent[];
  ioc: IOCData;
  tags: TagsData;
  evidence: EvidenceData;
  analysis_trace?: any[];
}

export async function fetchStats(): Promise<SystemStats> {
  const res = await fetch(`${API_BASE}/api/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) throw new Error('Failed to fetch health');
  return res.json();
}

export async function fetchCampaigns(): Promise<CampaignSummary[]> {
  const res = await fetch(`${API_BASE}/api/campaigns`);
  if (!res.ok) throw new Error('Failed to fetch campaigns');
  return res.json();
}

export async function fetchThreats(): Promise<ThreatSummary[]> {
  const res = await fetch(`${API_BASE}/api/threats`);
  if (!res.ok) throw new Error('Failed to fetch threats');
  return res.json();
}

export async function fetchUnifiedInvestigation(threatId: string): Promise<InvestigationPayload> {
  const res = await fetch(`${API_BASE}/api/threats/${threatId}/investigation`);
  if (!res.ok) throw new Error('Failed to fetch unified investigation');
  return res.json();
}
