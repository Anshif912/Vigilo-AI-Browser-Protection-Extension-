from urllib.parse import urlparse
from typing import Tuple, List
from sqlalchemy.orm import Session
from database.models import Campaign
from repositories.campaign_repository import CampaignRepository

class CampaignService:
    @staticmethod
    def extract_domain_fingerprint(url: str) -> List[str]:
        try:
            parsed = urlparse(url if "://" in url else "https://" + url)
            host = (parsed.hostname or "").lower()
            path = parsed.path.lower()
            combined = f"{host}{path}"
        except Exception:
            combined = url.lower()

        keywords = [
            "sbi", "paypal", "google", "microsoft", "amazon", "hdfc", "icici", "netflix", "meta",
            "login", "verify", "kyc", "banking", "secure", "account", "update", "auth", "credential"
        ]
        return [kw for kw in keywords if kw in combined]

    @staticmethod
    def process_campaign_association(
        db: Session,
        website_identity: str,
        attack_type: str,
        url: str,
        threat_score: int
    ) -> Tuple[Campaign, bool]:
        """
        Determines campaign association for incoming threat.
        Returns Tuple[Campaign, is_new: bool]
        """
        fingerprints = CampaignService.extract_domain_fingerprint(url)
        target_brand = website_identity if website_identity != "Unknown Brand" else "Deceptive Entity"

        # Check for existing matching campaign
        existing = CampaignRepository.find_matching_campaign(
            db=db,
            target_brand=target_brand,
            attack_type=attack_type,
            fingerprint_keywords=fingerprints
        )

        if existing:
            updated = CampaignRepository.increment_campaign_occurrence(db, existing.id)
            return (updated or existing, False)

        # Formulate new campaign name
        if target_brand and target_brand not in ["Unknown Brand", "Deceptive Entity"]:
            campaign_name = f"{target_brand} Phishing Campaign"
        else:
            campaign_name = f"Unverified {attack_type} Campaign"

        threat_level = "Critical" if threat_score >= 75 else "Suspicious"

        new_campaign = CampaignRepository.create_campaign(
            db=db,
            name=campaign_name,
            target_brand=target_brand,
            attack_type=attack_type,
            threat_level=threat_level
        )

        return (new_campaign, True)
