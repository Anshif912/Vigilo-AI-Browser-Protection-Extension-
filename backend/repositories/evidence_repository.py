import json
from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from database.models import ThreatEvidence

def current_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class EvidenceRepository:
    @staticmethod
    def create_evidence(
        db: Session,
        threat_id: str,
        ai_summary: str,
        reason: str,
        why_blocked: List[str],
        information_at_risk: List[str],
        screenshot_path: Optional[str] = None,
        html_snapshot: Optional[str] = None
    ) -> ThreatEvidence:
        now = current_iso_timestamp()
        evidence = ThreatEvidence(
            threat_id=threat_id,
            ai_summary=ai_summary,
            reason=reason,
            why_blocked=json.dumps(why_blocked),
            information_at_risk=json.dumps(information_at_risk),
            screenshot_path=screenshot_path,
            html_snapshot=html_snapshot,
            created_at=now
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        print(f"[Vigilo] Evidence Generated for Threat ID: {threat_id}")
        return evidence

    @staticmethod
    def get_evidence_by_threat_id(db: Session, threat_id: str) -> Optional[ThreatEvidence]:
        return db.query(ThreatEvidence).filter(ThreatEvidence.threat_id == threat_id).first()
