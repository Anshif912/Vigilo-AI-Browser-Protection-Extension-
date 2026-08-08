import json
from typing import List, Optional, Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from database.models import ThreatRecord

def current_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class ThreatRepository:
    @staticmethod
    def get_all_threats(db: Session, limit: int = 50) -> List[ThreatRecord]:
        return db.query(ThreatRecord).order_by(ThreatRecord.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_threat_by_id(db: Session, threat_id: str) -> Optional[ThreatRecord]:
        return db.query(ThreatRecord).filter(ThreatRecord.id == threat_id).first()

    @staticmethod
    def get_threat_by_analysis_id(db: Session, analysis_id: str) -> Optional[ThreatRecord]:
        return db.query(ThreatRecord).filter(ThreatRecord.analysis_id == analysis_id).first()

    @staticmethod
    def create_threat_record(
        db: Session,
        campaign_id: Optional[str],
        analysis: Any,
        domain: str,
        browser: str = "Chrome"
    ) -> ThreatRecord:
        now = analysis.timestamp if getattr(analysis, "timestamp", None) else current_iso_timestamp()
        
        record = ThreatRecord(
            campaign_id=campaign_id,
            analysis_id=analysis.analysis_id,
            timestamp=now,
            url=analysis.url,
            domain=domain,
            status=analysis.status,
            threat_score=analysis.threat_score,
            website_identity=analysis.website_identity,
            attack_type=analysis.attack_type,
            category=getattr(analysis, "category", "Credential Phishing"),
            sub_category=getattr(analysis, "sub_category", "Subdomain Impersonation"),
            confidence=getattr(analysis, "confidence", 85),
            confidence_level=getattr(analysis, "confidence_level", "High"),
            reason=analysis.reason,
            risk_reasoning_summary=getattr(analysis, "risk_reasoning_summary", analysis.reason),
            information_at_risk=json.dumps(analysis.information_at_risk),
            why_blocked=json.dumps(analysis.why_blocked),
            recommended_action=analysis.recommended_action,
            score_breakdown_json=json.dumps(analysis.score_breakdown) if analysis.score_breakdown else None,
            structured_evidence_json=json.dumps(analysis.structured_evidence) if analysis.structured_evidence else None,
            ioc_json=json.dumps(analysis.ioc) if analysis.ioc else None,
            analysis_trace_json=json.dumps(analysis.analysis_trace) if analysis.analysis_trace else None,
            data_provenance_json=json.dumps(analysis.data_provenance) if analysis.data_provenance else None,
            threat_fingerprint=getattr(analysis, "threat_fingerprint", None),
            connection_security=getattr(analysis, "connection_security", "Secure"),
            transport_protocol=getattr(analysis, "transport_protocol", "HTTPS"),
            tls_status=getattr(analysis, "tls_status", "TLS 1.3 / Enabled"),
            security_reason=getattr(analysis, "security_reason", ""),
            overall_status=getattr(analysis, "overall_status", "Safe"),
            engine_version=getattr(analysis, "engine_version", "3.1.0"),
            feature_schema=getattr(analysis, "feature_schema", "3.1"),
            brand_db_version=getattr(analysis, "brand_db_version", "2026.07"),
            external_intel_json=json.dumps(analysis.external_threat_intel) if analysis.external_threat_intel else None,
            browser=browser,
            created_at=now
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        print(f"[Vigilo] Single Source Threat Stored: {record.domain} (Score: {record.threat_score}, ID: {record.id})")
        return record

    @staticmethod
    def get_total_threats_count(db: Session) -> int:
        return db.query(ThreatRecord).count()

    @staticmethod
    def get_last_detection_timestamp(db: Session) -> Optional[str]:
        latest = db.query(ThreatRecord.timestamp).order_by(ThreatRecord.timestamp.desc()).first()
        return latest[0] if latest else None
