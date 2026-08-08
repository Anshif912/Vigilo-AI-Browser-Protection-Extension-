from typing import Optional
from sqlalchemy.orm import Session
from database.models import ThreatScoreBreakdown

class BreakdownRepository:
    @staticmethod
    def create_breakdown(
        db: Session,
        threat_id: str,
        brand_impersonation: int,
        domain_similarity: int,
        credential_collection: int,
        urgency_keywords: int,
        known_pattern: int,
        total_score: int
    ) -> ThreatScoreBreakdown:
        breakdown = ThreatScoreBreakdown(
            threat_id=threat_id,
            brand_impersonation=brand_impersonation,
            domain_similarity=domain_similarity,
            credential_collection=credential_collection,
            urgency_keywords=urgency_keywords,
            known_pattern=known_pattern,
            total_score=total_score
        )
        db.add(breakdown)
        db.commit()
        db.refresh(breakdown)
        return breakdown

    @staticmethod
    def get_by_threat_id(db: Session, threat_id: str) -> Optional[ThreatScoreBreakdown]:
        return db.query(ThreatScoreBreakdown).filter(ThreatScoreBreakdown.threat_id == threat_id).first()
