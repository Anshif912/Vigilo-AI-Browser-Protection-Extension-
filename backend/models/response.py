from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AnalyzeRequest(BaseModel):
    url: str = Field(..., example="https://fake-sbi-login.xyz")

class AnalyzeResponse(BaseModel):
    analysis_id: str
    timestamp: str
    url: str
    status: str  # Safe | Low Risk | Suspicious | High Risk | Critical
    threat_score: int  # 0 to 100
    confidence: int = 85  # 0 to 100%
    confidence_level: str = "High"  # High | Medium | Low
    website_identity: str
    attack_type: str
    category: str = "Credential Phishing"
    sub_category: str = "Subdomain Impersonation"
    reason: str
    risk_reasoning_summary: str = ""
    information_at_risk: List[str]
    why_blocked: List[str]
    recommended_action: str
    score_breakdown: Optional[List[Dict[str, Any]]] = None
    structured_evidence: Optional[Dict[str, Any]] = None
    ioc: Optional[Dict[str, Any]] = None
    analysis_trace: Optional[List[Dict[str, Any]]] = None
    data_provenance: Optional[Dict[str, str]] = None
    threat_fingerprint: Optional[str] = None
    # v3.1 Connection Security & Overall Status Model
    connection_security: str = "Secure"      # Secure | Not Secure
    transport_protocol: str = "HTTPS"         # HTTPS | HTTP
    tls_status: str = "TLS 1.3 / Enabled"     # TLS 1.3 / Enabled | Disabled
    security_reason: str = ""
    overall_status: str = "Safe"              # Safe | Low Risk | Suspicious | High Risk | Critical

    # v3.2 AI Threat Explanation Engine Model
    ai_explanation: Optional[Dict[str, Any]] = None

    engine_version: str = "3.2.0"
    feature_schema: str = "3.2"
    brand_db_version: str = "2026.07"
    external_threat_intel: Optional[Dict[str, Any]] = None
    threat_timeline: Optional[List[Dict[str, Any]]] = None

