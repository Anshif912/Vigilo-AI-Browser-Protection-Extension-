from typing import List
from sqlalchemy.orm import Session
from database.models import ThreatTag

class TagRepository:
    @staticmethod
    def create_tag(db: Session, threat_id: str, tag: str, confidence: int = 95) -> ThreatTag:
        t = ThreatTag(
            threat_id=threat_id,
            tag=tag,
            confidence=confidence
        )
        db.add(t)
        db.commit()
        db.refresh(t)
        return t

    @staticmethod
    def get_by_threat_id(db: Session, threat_id: str) -> List[ThreatTag]:
        return db.query(ThreatTag).filter(ThreatTag.threat_id == threat_id).all()
