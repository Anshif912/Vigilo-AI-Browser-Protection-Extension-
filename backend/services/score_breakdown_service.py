from typing import Dict, Any, List
from sqlalchemy.orm import Session
from repositories.breakdown_repository import BreakdownRepository

class ScoreBreakdownService:
    @staticmethod
    def calculate_and_store_breakdown(
        db: Session,
        threat_id: str,
        total_score: int,
        url: str,
        identity: str,
        at_risk: List[str]
    ) -> Dict[str, Any]:
        url_lower = url.lower()

        # Dynamic Factor Computation based on actual detection features
        brand_score = 30 if (identity and identity != "Unknown Brand") else 0
        cred_score = 25 if any(term in at_risk for term in ["Username", "Password", "OTP", "Bank Account"]) else 10
        urgency_score = 15 if any(kw in url_lower for kw in ["login", "verify", "kyc", "secure", "update"]) else 5
        domain_score = 15 if any(tld in url_lower for tld in [".xyz", ".tech", ".top", ".online", ".site", ".click"]) else 5

        current_sum = brand_score + cred_score + urgency_score + domain_score
        pattern_score = max(total_score - current_sum, 0)

        breakdown = BreakdownRepository.create_breakdown(
            db=db,
            threat_id=threat_id,
            brand_impersonation=brand_score,
            domain_similarity=domain_score,
            credential_collection=cred_score,
            urgency_keywords=urgency_score,
            known_pattern=pattern_score,
            total_score=total_score
        )

        factors = [
            {"factor": "Brand Impersonation", "score": brand_score},
            {"factor": "Credential Collection", "score": cred_score},
            {"factor": "Urgency & Login Keywords", "score": urgency_score},
            {"factor": "Domain Anomaly & TLD", "score": domain_score},
            {"factor": "Known Phishing Signature Pattern", "score": pattern_score}
        ]

        print(f"[Vigilo] Threat Score Breakdown Generated for Threat ID: {threat_id}")
        return {"score": total_score, "breakdown": factors}
