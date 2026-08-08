from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from database.models import Campaign, ThreatRecord

def current_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class CampaignRepository:
    @staticmethod
    def get_all_campaigns(db: Session) -> List[Campaign]:
        return db.query(Campaign).order_by(Campaign.last_seen.desc()).all()

    @staticmethod
    def get_campaign_by_id(db: Session, campaign_id: str) -> Optional[Campaign]:
        return db.query(Campaign).filter(Campaign.id == campaign_id).first()

    @staticmethod
    def find_matching_campaign(
        db: Session,
        target_brand: str,
        attack_type: str,
        fingerprint_keywords: List[str]
    ) -> Optional[Campaign]:
        """
        Lightweight Domain Fingerprinting Matcher:
        Matches existing campaign if target_brand matches OR if fingerprint keywords overlap.
        """
        campaigns = db.query(Campaign).filter(Campaign.status == "ACTIVE").all()

        # 1. Direct Brand Match
        if target_brand and target_brand != "Unknown Brand":
            for camp in campaigns:
                if camp.target_brand.lower() == target_brand.lower():
                    return camp

        # 2. Fingerprint Keyword Overlap
        if fingerprint_keywords:
            for camp in campaigns:
                camp_name_lower = camp.name.lower()
                for kw in fingerprint_keywords:
                    if kw in camp_name_lower or kw in camp.target_brand.lower():
                        return camp

        return None

    @staticmethod
    def create_campaign(
        db: Session,
        name: str,
        target_brand: str,
        attack_type: str,
        threat_level: str = "Critical"
    ) -> Campaign:
        now = current_iso_timestamp()
        campaign = Campaign(
            name=name,
            target_brand=target_brand,
            attack_type=attack_type,
            status="ACTIVE",
            state="NEW",
            threat_level=threat_level,
            first_seen=now,
            last_seen=now,
            occurrences=1,
            created_at=now
        )
        db.add(campaign)
        db.commit()
        db.refresh(campaign)
        print(f"[Vigilo] New Campaign Created: {campaign.name} (ID: {campaign.id})")
        return campaign

    @staticmethod
    def increment_campaign_occurrence(db: Session, campaign_id: str) -> Optional[Campaign]:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            campaign.occurrences += 1
            campaign.last_seen = current_iso_timestamp()
            db.commit()
            db.refresh(campaign)
            print(f"[Vigilo] Campaign Updated: {campaign.name} (Occurrences: {campaign.occurrences})")
        return campaign

    @staticmethod
    def get_campaign_related_urls(db: Session, campaign_id: str) -> List[str]:
        """
        Derived normalized URL list from ThreatRecord table
        """
        records = db.query(ThreatRecord.url).filter(ThreatRecord.campaign_id == campaign_id).distinct().all()
        return [r[0] for r in records]
