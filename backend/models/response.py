from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AnalyzeRequest(BaseModel):
    url: str = Field(..., example="https://fake-sbi-login.xyz")

class AnalyzeResponse(BaseModel):
    analysis_id: str
    timestamp: str
    url: str
    status: str  # Safe | Low Risk | Suspicious | High Risk | Critical | Unverified
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
    
    # v4.0 Multi-Signal 4-Status Architecture
    technical_status: str = "Reachable"           # Reachable | Unreachable / DNS Failure | Connection Timeout | Unverified
    connection_security: str = "HTTPS Secure"      # HTTPS Secure | HTTP Insecure | HTTPS Cert Invalid | Unverified
    reputation_status: str = "Clean Reputation"    # Clean Reputation | Suspicious Reputation | High Risk Reputation | Unverified
    threat_status: str = "Safe"                    # Safe | Low Risk | Suspicious | High Risk | Critical | Unverified
    overall_status: str = "Safe"                   # Verified Safe | Low Risk | Unverified | Suspicious | High Risk | Critical

    transport_protocol: str = "HTTPS"
    tls_status: str = "TLS 1.3 / Enabled"
    security_reason: str = ""

    # Technical Telemetry
    dns_details: Optional[Dict[str, Any]] = None
    redirect_chain: Optional[List[str]] = None
    content_intel: Optional[Dict[str, Any]] = None

    ai_explanation: Optional[Dict[str, Any]] = None
    engine_version: str = "4.0.0"
    feature_schema: str = "4.0"
    brand_db_version: str = "2026.08"
    external_threat_intel: Optional[Dict[str, Any]] = None
    threat_timeline: Optional[List[Dict[str, Any]]] = None
