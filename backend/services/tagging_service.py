from typing import Dict, Any, List
from sqlalchemy.orm import Session
from repositories.tag_repository import TagRepository

class TaggingService:
    @staticmethod
    def generate_and_store_tags(
        db: Session,
        threat_id: str,
        url: str,
        identity: str,
        attack_type: str,
        at_risk: List[str]
    ) -> Dict[str, Any]:
        url_lower = url.lower()
        tags_data = []

        # 1. Banking / Financial tag
        if identity != "Unknown Brand" or any(kw in url_lower for kw in ["bank", "pay", "kyc", "card", "sbi"]):
            t = TagRepository.create_tag(db, threat_id, "Banking", confidence=100)
            tags_data.append({"tag": t.tag, "confidence": t.confidence})

        # 2. Credential Theft tag
        if "credential" in attack_type.lower() or any(r in at_risk for r in ["Username", "Password", "OTP"]):
            t = TagRepository.create_tag(db, threat_id, "Credential Theft", confidence=95)
            tags_data.append({"tag": t.tag, "confidence": t.confidence})

        # 3. Clone Website tag
        t_clone = TagRepository.create_tag(db, threat_id, "Clone Website", confidence=92)
        tags_data.append({"tag": t_clone.tag, "confidence": t_clone.confidence})

        # 4. High Confidence tag
        t_conf = TagRepository.create_tag(db, threat_id, "High Confidence Pattern", confidence=90)
        tags_data.append({"tag": t_conf.tag, "confidence": t_conf.confidence})

        # 5. Urgency Indicator tag
        if any(kw in url_lower for kw in ["login", "verify", "secure", "kyc", "update"]):
            t_urg = TagRepository.create_tag(db, threat_id, "Urgency Indicator", confidence=85)
            tags_data.append({"tag": t_urg.tag, "confidence": t_urg.confidence})

        # Determine Risk Category
        if "banking" in attack_type.lower() or "bank" in url_lower or identity != "Unknown Brand":
            risk_category = "Financial Fraud"
        elif "credential" in attack_type.lower() or "login" in url_lower:
            risk_category = "Credential Theft"
        else:
            risk_category = "Identity Fraud"

        print(f"[Vigilo] Threat Tagged for Threat ID: {threat_id} (Category: {risk_category}, Tags: {len(tags_data)})")

        return {
            "risk_category": risk_category,
            "tags": tags_data
        }
