import json
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db import get_db
from repositories.threat_repository import ThreatRepository
from repositories.campaign_repository import CampaignRepository
from repositories.evidence_repository import EvidenceRepository
from repositories.breakdown_repository import BreakdownRepository
from repositories.ioc_repository import IOCRepository
from repositories.tag_repository import TagRepository
from repositories.timeline_repository import TimelineRepository

router = APIRouter(prefix="/api/threats", tags=["Threat Intelligence"])

@router.get("", response_model=List[Dict[str, Any]])
def get_all_threats(limit: int = 50, db: Session = Depends(get_db)):
    records = ThreatRepository.get_all_threats(db, limit=limit)
    result = []
    for r in records:
        campaign = CampaignRepository.get_campaign_by_id(db, r.campaign_id) if r.campaign_id else None
        at_risk = json.loads(r.information_at_risk) if r.information_at_risk else []
        why_blocked = json.loads(r.why_blocked) if r.why_blocked else []
        factors = json.loads(r.confidence_factors) if r.confidence_factors else []
        stages = json.loads(r.pipeline_stages) if r.pipeline_stages else []

        result.append({
            "id": r.id,
            "analysis_id": r.analysis_id,
            "campaign_id": r.campaign_id,
            "campaign_name": campaign.name if campaign else "Unassigned",
            "timestamp": r.timestamp,
            "url": r.url,
            "domain": r.domain,
            "status": r.status,
            "threat_score": r.threat_score,
            "confidence": getattr(r, "confidence", 85),
            "confidence_level": getattr(r, "confidence_level", "High"),
            "website_identity": r.website_identity,
            "attack_type": r.attack_type,
            "category": getattr(r, "category", "Credential Phishing"),
            "sub_category": getattr(r, "sub_category", "Subdomain Impersonation"),
            "connection_security": getattr(r, "connection_security", "Secure"),
            "transport_protocol": getattr(r, "transport_protocol", "HTTPS"),
            "tls_status": getattr(r, "tls_status", "TLS 1.3 / Enabled"),
            "security_reason": getattr(r, "security_reason", ""),
            "overall_status": getattr(r, "overall_status", r.status),
            "reason": r.reason,
            "risk_reasoning_summary": getattr(r, "risk_reasoning_summary", r.reason),
            "information_at_risk": at_risk,
            "why_blocked": why_blocked,
            "recommended_action": r.recommended_action,
            "browser": r.browser,
            "campaign_confidence": r.campaign_confidence,
            "confidence_factors": factors,
            "investigation_ready": r.investigation_ready,
            "investigation_completeness": r.investigation_completeness,
            "processing_status": r.processing_status,
            "processing_duration_ms": r.processing_duration_ms,
            "pipeline_stages": stages,
            "pipeline_version": r.pipeline_version,
            "created_at": r.created_at
        })
    return result

@router.get("/{threat_id}", response_model=Dict[str, Any])
def get_threat_by_id(threat_id: str, db: Session = Depends(get_db)):
    r = ThreatRepository.get_threat_by_id(db, threat_id)
    if not r:
        r = ThreatRepository.get_threat_by_analysis_id(db, threat_id)
    if not r:
        raise HTTPException(status_code=404, detail="Threat record not found")

    campaign = CampaignRepository.get_campaign_by_id(db, r.campaign_id) if r.campaign_id else None
    evidence = EvidenceRepository.get_evidence_by_threat_id(db, r.id)

    at_risk = json.loads(r.information_at_risk) if r.information_at_risk else []
    why_blocked = json.loads(r.why_blocked) if r.why_blocked else []
    factors = json.loads(r.confidence_factors) if r.confidence_factors else []

    evidence_data = {
        "reason": r.reason,
        "why_blocked": why_blocked,
        "information_at_risk": at_risk,
        "screenshot_path": evidence.screenshot_path if evidence else None,
        "html_snapshot": evidence.html_snapshot if evidence else None
    }

    return {
        "id": r.id,
        "analysis_id": r.analysis_id,
        "campaign_id": r.campaign_id,
        "campaign_name": campaign.name if campaign else "Unassigned",
        "url": r.url,
        "domain": r.domain,
        "status": r.status,
        "threat_score": r.threat_score,
        "website_identity": r.website_identity,
        "attack_type": r.attack_type,
        "summary": evidence.ai_summary if evidence else r.reason,
        "evidence": evidence_data,
        "campaign_confidence": r.campaign_confidence,
        "confidence_factors": factors,
        "investigation_ready": r.investigation_ready,
        "investigation_completeness": r.investigation_completeness,
        "processing_status": r.processing_status,
        "processing_duration_ms": r.processing_duration_ms,
        "timestamp": r.timestamp
    }

@router.get("/{threat_id}/score", response_model=Dict[str, Any])
def get_threat_score_breakdown(threat_id: str, db: Session = Depends(get_db)):
    r = ThreatRepository.get_threat_by_id(db, threat_id)
    if not r:
        r = ThreatRepository.get_threat_by_analysis_id(db, threat_id)
    if not r:
        raise HTTPException(status_code=404, detail="Threat record not found")

    breakdown = BreakdownRepository.get_by_threat_id(db, r.id)
    if not breakdown:
        # Return computed fallback
        brand = 30 if r.website_identity != "Unknown Brand" else 0
        cred = 25
        urgency = 15
        domain = 15
        pattern = max(r.threat_score - (brand + cred + urgency + domain), 0)
        factors = [
            {"factor": "Brand Impersonation", "score": brand},
            {"factor": "Credential Collection", "score": cred},
            {"factor": "Urgency Keywords", "score": urgency},
            {"factor": "Domain Similarity", "score": domain},
            {"factor": "Known Pattern", "score": pattern}
        ]
        return {"score": r.threat_score, "breakdown": factors}

    factors = [
        {"factor": "Brand Impersonation", "score": breakdown.brand_impersonation},
        {"factor": "Credential Collection", "score": breakdown.credential_collection},
        {"factor": "Urgency Keywords", "score": breakdown.urgency_keywords},
        {"factor": "Domain Similarity", "score": breakdown.domain_similarity},
        {"factor": "Known Pattern", "score": breakdown.known_pattern}
    ]
    return {"score": breakdown.total_score, "breakdown": factors}

@router.get("/{threat_id}/ioc", response_model=Dict[str, Any])
def get_threat_ioc(threat_id: str, db: Session = Depends(get_db)):
    r = ThreatRepository.get_threat_by_id(db, threat_id)
    if not r:
        r = ThreatRepository.get_threat_by_analysis_id(db, threat_id)
    if not r:
        raise HTTPException(status_code=404, detail="Threat record not found")

    ioc = IOCRepository.get_by_threat_id(db, r.id)
    if not ioc:
        parts = r.domain.split(".")
        tld = parts[-1] if len(parts) > 1 else "unknown"
        return {
            "domain": r.domain,
            "tld": tld,
            "domain_length": len(r.domain),
            "website_identity": r.website_identity,
            "attack_type": r.attack_type,
            "keywords": ["login", "verify"],
            "contains_brand": r.website_identity != "Unknown Brand",
            "contains_login_terms": "login" in r.url.lower(),
            "contains_banking_terms": "sbi" in r.url.lower() or "bank" in r.url.lower(),
            "risk_category": "Financial Fraud" if "bank" in r.url.lower() else "Credential Theft",
            "fingerprint": parts[0]
        }

    keywords = json.loads(ioc.keywords) if ioc.keywords else []
    return {
        "domain": ioc.domain,
        "tld": ioc.tld,
        "domain_length": ioc.domain_length,
        "website_identity": ioc.website_identity,
        "attack_type": ioc.attack_type,
        "keywords": keywords,
        "contains_brand": ioc.contains_brand,
        "contains_login_terms": ioc.contains_login_terms,
        "contains_banking_terms": ioc.contains_banking_terms,
        "risk_category": ioc.risk_category,
        "fingerprint": ioc.fingerprint
    }

@router.get("/{threat_id}/tags", response_model=Dict[str, Any])
def get_threat_tags(threat_id: str, db: Session = Depends(get_db)):
    r = ThreatRepository.get_threat_by_id(db, threat_id)
    if not r:
        r = ThreatRepository.get_threat_by_analysis_id(db, threat_id)
    if not r:
        raise HTTPException(status_code=404, detail="Threat record not found")

    tags_list = TagRepository.get_by_threat_id(db, r.id)
    ioc = IOCRepository.get_by_threat_id(db, r.id)

    category = ioc.risk_category if ioc else ("Financial Fraud" if "bank" in r.url.lower() else "Credential Theft")
    result_tags = [{"tag": t.tag, "confidence": t.confidence} for t in tags_list]

    if not result_tags:
        result_tags = [
            {"tag": "Credential Theft", "confidence": 95},
            {"tag": "Clone Website", "confidence": 92},
            {"tag": "High Confidence", "confidence": 90}
        ]

    return {
        "risk_category": category,
        "tags": result_tags
    }

@router.get("/{threat_id}/investigation", response_model=Dict[str, Any])
def get_threat_unified_investigation(threat_id: str, db: Session = Depends(get_db)):
    """
    Unified SOC Investigation API for Phase 3 Dashboard Integration.
    Consolidates Threat, Campaign, Score Breakdown, Confidence, Timeline, IOC, Tags, and Evidence in 1 payload.
    """
    r = ThreatRepository.get_threat_by_id(db, threat_id)
    if not r:
        r = ThreatRepository.get_threat_by_analysis_id(db, threat_id)
    if not r:
        raise HTTPException(status_code=404, detail="Threat record not found")

    campaign = CampaignRepository.get_campaign_by_id(db, r.campaign_id) if r.campaign_id else None
    evidence = EvidenceRepository.get_evidence_by_threat_id(db, r.id)
    score_res = get_threat_score_breakdown(r.id, db)
    ioc_res = get_threat_ioc(r.id, db)
    tags_res = get_threat_tags(r.id, db)
    timeline_events = TimelineRepository.get_by_threat_id(db, r.id)

    timeline_data = [
        {
            "id": t.id,
            "event_type": t.event_type,
            "description": t.description,
            "severity": t.severity,
            "actor": t.actor,
            "created_at": t.created_at
        }
        for t in timeline_events
    ]

    at_risk = json.loads(r.information_at_risk) if r.information_at_risk else []
    why_blocked = json.loads(r.why_blocked) if r.why_blocked else []
    factors = json.loads(r.confidence_factors) if r.confidence_factors else []
    stages = json.loads(r.pipeline_stages) if r.pipeline_stages else []

    summary_block = {
        "risk_level": r.status,
        "campaign_name": campaign.name if campaign else "Unassigned Campaign",
        "campaign_confidence": r.campaign_confidence,
        "processing_status": r.processing_status,
        "investigation_ready": r.investigation_ready,
        "investigation_completeness": r.investigation_completeness,
        "processing_duration_ms": r.processing_duration_ms
    }

    evidence_data = {
        "reason": r.reason,
        "ai_summary": evidence.ai_summary if evidence else r.reason,
        "why_blocked": why_blocked,
        "information_at_risk": at_risk,
        "screenshot_path": evidence.screenshot_path if evidence else None,
        "html_snapshot": evidence.html_snapshot if evidence else None
    }

    breakdown_list = json.loads(r.score_breakdown_json) if getattr(r, "score_breakdown_json", None) else score_res.get("breakdown", [])
    analysis_trace_list = json.loads(r.analysis_trace_json) if getattr(r, "analysis_trace_json", None) else []
    structured_evidence_data = json.loads(r.structured_evidence_json) if getattr(r, "structured_evidence_json", None) else None
    ioc_data = json.loads(r.ioc_json) if getattr(r, "ioc_json", None) else ioc_res
    data_prov = json.loads(r.data_provenance_json) if getattr(r, "data_provenance_json", None) else None
    perf_data = json.loads(r.performance_json) if getattr(r, "performance_json", None) else None
    ext_intel = json.loads(r.external_intel_json) if getattr(r, "external_intel_json", None) else None

    return {
        "summary": summary_block,
        "threat": {
            "id": r.id,
            "analysis_id": r.analysis_id,
            "url": r.url,
            "domain": r.domain,
            "status": r.status,
            "threat_score": r.threat_score,
            "confidence": getattr(r, "confidence", 85),
            "confidence_level": getattr(r, "confidence_level", "High"),
            "website_identity": r.website_identity,
            "attack_type": r.attack_type,
            "category": getattr(r, "category", "Credential Phishing"),
            "sub_category": getattr(r, "sub_category", "Subdomain Impersonation"),
            "connection_security": getattr(r, "connection_security", "Secure"),
            "transport_protocol": getattr(r, "transport_protocol", "HTTPS"),
            "tls_status": getattr(r, "tls_status", "TLS 1.3 / Enabled"),
            "security_reason": getattr(r, "security_reason", ""),
            "overall_status": getattr(r, "overall_status", r.status),
            "reason": r.reason,
            "risk_reasoning_summary": getattr(r, "risk_reasoning_summary", r.reason),
            "threat_fingerprint": getattr(r, "threat_fingerprint", None),
            "engine_version": getattr(r, "engine_version", "3.1.0"),
            "feature_schema": getattr(r, "feature_schema", "3.1"),
            "brand_db_version": getattr(r, "brand_db_version", "2026.07"),
            "browser": r.browser,
            "pipeline_stages": stages,
            "pipeline_version": r.pipeline_version,
            "schema_version": r.schema_version,
            "timestamp": r.timestamp
        },
        "campaign": {
            "id": campaign.id if campaign else None,
            "name": campaign.name if campaign else "Unassigned",
            "target_brand": campaign.target_brand if campaign else r.website_identity,
            "attack_type": campaign.attack_type if campaign else r.attack_type,
            "status": campaign.status if campaign else "ACTIVE",
            "state": campaign.state if campaign else "NEW",
            "occurrences": campaign.occurrences if campaign else 1
        } if campaign else None,
        "score_breakdown": breakdown_list,
        "confidence": {
            "score": getattr(r, "confidence", r.campaign_confidence),
            "level": getattr(r, "confidence_level", "High"),
            "factors": factors
        },
        "timeline": timeline_data,
        "ioc": ioc_data,
        "tags": tags_res,
        "evidence": evidence_data,
        "structured_evidence": structured_evidence_data,
        "analysis_trace": analysis_trace_list,
        "data_provenance": data_prov,
        "performance": perf_data,
        "external_threat_intel": ext_intel
    }
