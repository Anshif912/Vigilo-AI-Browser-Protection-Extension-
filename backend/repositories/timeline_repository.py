from typing import List, Optional
from sqlalchemy.orm import Session
from database.models import ThreatTimeline

class TimelineRepository:
    @staticmethod
    def create_event(
        db: Session,
        event_type: str,
        description: str,
        severity: str = "INFO",
        actor: str = "SYSTEM",
        campaign_id: Optional[str] = None,
        threat_id: Optional[str] = None
    ) -> ThreatTimeline:
        event = ThreatTimeline(
            campaign_id=campaign_id,
            threat_id=threat_id,
            event_type=event_type,
            description=description,
            severity=severity,
            actor=actor
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def get_by_campaign_id(db: Session, campaign_id: str) -> List[ThreatTimeline]:
        return db.query(ThreatTimeline).filter(ThreatTimeline.campaign_id == campaign_id).order_by(ThreatTimeline.created_at.asc()).all()

    @staticmethod
    def get_by_threat_id(db: Session, threat_id: str) -> List[ThreatTimeline]:
        return db.query(ThreatTimeline).filter(ThreatTimeline.threat_id == threat_id).order_by(ThreatTimeline.created_at.asc()).all()
