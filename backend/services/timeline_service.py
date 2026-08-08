from typing import Optional
from sqlalchemy.orm import Session
from repositories.timeline_repository import TimelineRepository

class TimelineService:
    @staticmethod
    def record_event(
        db: Session,
        event_type: str,
        description: str,
        severity: str = "INFO",
        actor: str = "SYSTEM",
        campaign_id: Optional[str] = None,
        threat_id: Optional[str] = None
    ):
        event = TimelineRepository.create_event(
            db=db,
            event_type=event_type,
            description=description,
            severity=severity,
            actor=actor,
            campaign_id=campaign_id,
            threat_id=threat_id
        )
        print(f"[Vigilo] Timeline Event Added [{severity} | {actor}]: {event_type} - {description}")
        return event
