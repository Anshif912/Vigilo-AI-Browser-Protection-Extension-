import json
from typing import List, Optional
from sqlalchemy.orm import Session
from database.models import ThreatIOC

class IOCRepository:
    @staticmethod
    def create_ioc(
        db: Session,
        threat_id: str,
        domain: str,
        tld: str,
        domain_length: int,
        website_identity: str,
        attack_type: str,
        keywords: List[str],
        contains_brand: bool,
        contains_login_terms: bool,
        contains_banking_terms: bool,
        risk_category: str,
        fingerprint: str
    ) -> ThreatIOC:
        ioc = ThreatIOC(
            threat_id=threat_id,
            domain=domain,
            tld=tld,
            domain_length=domain_length,
            website_identity=website_identity,
            attack_type=attack_type,
            keywords=json.dumps(keywords),
            contains_brand=contains_brand,
            contains_login_terms=contains_login_terms,
            contains_banking_terms=contains_banking_terms,
            risk_category=risk_category,
            fingerprint=fingerprint
        )
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        return ioc

    @staticmethod
    def get_by_threat_id(db: Session, threat_id: str) -> Optional[ThreatIOC]:
        return db.query(ThreatIOC).filter(ThreatIOC.threat_id == threat_id).first()
