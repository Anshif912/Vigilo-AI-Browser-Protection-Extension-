from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database.db import get_db
from database.models import Campaign, ThreatRecord

router = APIRouter(prefix="/api/stats", tags=["Intelligence Statistics"])

@router.get("", response_model=Dict[str, Any])
def get_intelligence_stats(db: Session = Depends(get_db)):
    total_threats = db.query(ThreatRecord).count()
    active_campaigns = db.query(Campaign).filter(Campaign.status == "ACTIVE").count()
    critical_campaigns = db.query(Campaign).filter(Campaign.threat_level == "Critical").count()

    latest_threat = db.query(ThreatRecord.timestamp).order_by(ThreatRecord.timestamp.desc()).first()
    last_detection = latest_threat[0] if latest_threat else None

    return {
        "total_threats": total_threats,
        "active_campaigns": active_campaigns,
        "critical_campaigns": critical_campaigns,
        "last_detection": last_detection
    }
