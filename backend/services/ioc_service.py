from urllib.parse import urlparse
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from repositories.ioc_repository import IOCRepository

class IOCService:
    @staticmethod
    def extract_and_store_ioc(
        db: Session,
        threat_id: str,
        url: str,
        domain: str,
        identity: str,
        attack_type: str
    ) -> Dict[str, Any]:
        url_lower = url.lower()
        domain_lower = domain.lower()

        # Extract TLD
        parts = domain_lower.split(".")
        tld = parts[-1] if len(parts) > 1 else "unknown"
        domain_length = len(domain_lower)

        # Keyword checks
        keywords_list = ["login", "verify", "secure", "kyc", "update", "account", "auth", "signin", "bank", "sbi", "paypal"]
        matched_kw = [kw for kw in keywords_list if kw in url_lower]

        contains_brand = identity != "Unknown Brand"
        contains_login_terms = any(term in url_lower for term in ["login", "signin", "auth", "credential"])
        contains_banking_terms = any(term in url_lower for term in ["sbi", "bank", "pay", "kyc", "card", "wallet", "paypal"])

        # Determine Risk Category
        if contains_banking_terms or "banking" in attack_type.lower():
            risk_category = "Financial Fraud"
        elif contains_login_terms or "credential" in attack_type.lower():
            risk_category = "Credential Theft"
        else:
            risk_category = "Identity Fraud"

        # Generate Fingerprint
        fp_parts = matched_kw if matched_kw else [parts[0]]
        fingerprint = "-".join(fp_parts[:3])

        ioc = IOCRepository.create_ioc(
            db=db,
            threat_id=threat_id,
            domain=domain_lower,
            tld=tld,
            domain_length=domain_length,
            website_identity=identity,
            attack_type=attack_type,
            keywords=matched_kw,
            contains_brand=contains_brand,
            contains_login_terms=contains_login_terms,
            contains_banking_terms=contains_banking_terms,
            risk_category=risk_category,
            fingerprint=fingerprint
        )

        print(f"[Vigilo] IOC Extracted for Threat ID: {threat_id} (Fingerprint: {fingerprint})")
        return {
            "domain": domain_lower,
            "tld": tld,
            "domain_length": domain_length,
            "website_identity": identity,
            "attack_type": attack_type,
            "keywords": matched_kw,
            "contains_brand": contains_brand,
            "contains_login_terms": contains_login_terms,
            "contains_banking_terms": contains_banking_terms,
            "risk_category": risk_category,
            "fingerprint": fingerprint
        }
