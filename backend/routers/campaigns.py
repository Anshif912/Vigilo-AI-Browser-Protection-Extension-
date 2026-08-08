from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db import get_db
from repositories.campaign_repository import CampaignRepository
from repositories.timeline_repository import TimelineRepository

router = APIRouter(prefix="/api/campaigns", tags=["Campaign Intelligence"])

@router.get("", response_model=List[Dict[str, Any]])
def get_all_campaigns(db: Session = Depends(get_db)):
    campaigns = CampaignRepository.get_all_campaigns(db)
    result = []
    for c in campaigns:
        related_urls = CampaignRepository.get_campaign_related_urls(db, c.id)
        result.append({
            "id": c.id,
            "name": c.name,
            "target_brand": c.target_brand,
            "attack_type": c.attack_type,
            "status": c.status,
            "state": c.state,
            "threat_level": c.threat_level,
            "total_occurrences": c.occurrences,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
            "related_urls": related_urls
        })
    return result

@router.get("/{campaign_id}", response_model=Dict[str, Any])
def get_campaign_by_id(campaign_id: str, db: Session = Depends(get_db)):
    c = CampaignRepository.get_campaign_by_id(db, campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")

    related_urls = CampaignRepository.get_campaign_related_urls(db, c.id)
    threats_data = [
        {
            "id": t.id,
            "analysis_id": t.analysis_id,
            "url": t.url,
            "status": t.status,
            "threat_score": t.threat_score,
            "timestamp": t.timestamp
        }
        for t in c.threat_records
    ]

    return {
        "id": c.id,
        "name": c.name,
        "target_brand": c.target_brand,
        "attack_type": c.attack_type,
        "status": c.status,
        "state": c.state,
        "threat_level": c.threat_level,
        "total_occurrences": c.occurrences,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "related_urls": related_urls,
        "threats": threats_data
    }

@router.get("/{campaign_id}/timeline", response_model=List[Dict[str, Any]])
def get_campaign_timeline(campaign_id: str, db: Session = Depends(get_db)):
    c = CampaignRepository.get_campaign_by_id(db, campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")

    events = TimelineRepository.get_by_campaign_id(db, campaign_id)
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "description": e.description,
            "severity": e.severity,
            "actor": e.actor,
            "threat_id": e.threat_id,
            "created_at": e.created_at
        }
        for e in events
    ]
