import json
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from database.models import ThreatRecord, Campaign

class CampaignConfidenceService:
    @staticmethod
    def calculate_confidence(
        db: Session,
        threat: ThreatRecord,
        campaign: Campaign
    ) -> Dict[str, Any]:
        factors = []
        confidence_score = 0

        # 1. Brand Match (30 pts)
        if threat.website_identity and threat.website_identity != "Unknown Brand":
            if threat.website_identity.lower() in campaign.target_brand.lower() or campaign.target_brand.lower() in threat.website_identity.lower():
                confidence_score += 30
                factors.append({"factor": "Brand Match", "weight": 30})
            else:
                confidence_score += 15
                factors.append({"factor": "Partial Brand Similarity", "weight": 15})
        else:
            confidence_score += 10
            factors.append({"factor": "Generic Brand Heuristic", "weight": 10})

        # 2. Attack Type Match (25 pts)
        if threat.attack_type.lower() == campaign.attack_type.lower():
            confidence_score += 25
            factors.append({"factor": "Attack Type Match", "weight": 25})
        else:
            confidence_score += 15
            factors.append({"factor": "Related Attack Class", "weight": 15})

        # 3. Fingerprint & Keyword Similarity (25 pts)
        keywords = ["sbi", "paypal", "login", "verify", "kyc", "bank", "secure"]
        matched_kw = [kw for kw in keywords if kw in threat.url.lower()]
        if matched_kw:
            confidence_score += 25
            factors.append({"factor": "Fingerprint Similarity", "weight": 25})
        else:
            confidence_score += 15
            factors.append({"factor": "Domain Structural Pattern", "weight": 15})

        # 4. Historical Pattern Overlap (15 pts)
        if campaign.occurrences > 1:
            confidence_score += 15
            factors.append({"factor": "Historical Campaign Pattern", "weight": 15})
        else:
            confidence_score += 10
            factors.append({"factor": "Initial Campaign Indicator", "weight": 10})

        confidence_score = min(max(confidence_score, 50), 98)

        # Update ThreatRecord
        threat.campaign_confidence = confidence_score
        threat.confidence_factors = json.dumps(factors)
        db.commit()
        db.refresh(threat)

        print(f"[Vigilo] Campaign Confidence Calculated: {confidence_score}% for Threat ID: {threat.id}")
        return {
            "campaign_confidence": confidence_score,
            "confidence_factors": factors
        }
