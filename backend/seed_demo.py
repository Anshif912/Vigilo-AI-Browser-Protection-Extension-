import json
from database.db import SessionLocal, init_db
from repositories.campaign_repository import CampaignRepository
from repositories.threat_repository import ThreatRepository
from repositories.evidence_repository import EvidenceRepository

def seed_demo_data():
    init_db()
    db = SessionLocal()
    try:
        print("="*60)
        print("[Vigilo] Seeding Demo Threat Intelligence Data...")
        print("="*60)

        # 1. SBI Campaign
        sbi_camp = CampaignRepository.create_campaign(
            db=db,
            name="Fake SBI Banking Campaign",
            target_brand="SBI Internet Banking",
            attack_type="Credential Theft",
            threat_level="Critical"
        )
        t1 = ThreatRepository.create_threat_record(
            db=db,
            campaign_id=sbi_camp.id,
            analysis_id="demo-sbi-1",
            url="https://fake-sbi-login.xyz",
            domain="fake-sbi-login.xyz",
            status="Critical",
            threat_score=96,
            website_identity="SBI Internet Banking",
            attack_type="Credential Theft",
            reason="This website impersonates SBI to steal banking credentials and OTPs.",
            information_at_risk=["Username", "Password", "OTP"],
            why_blocked=["Fake banking login page", "Active phishing campaign"],
            recommended_action="Use official SBI website (onlinesbi.sbi)."
        )
        EvidenceRepository.create_evidence(
            db=db,
            threat_id=t1.id,
            ai_summary="This phishing campaign impersonates SBI Internet Banking. Primary objective is credential theft.",
            reason=t1.reason,
            why_blocked=["Fake banking login page", "Active phishing campaign"],
            information_at_risk=["Username", "Password", "OTP"]
        )

        t2 = ThreatRepository.create_threat_record(
            db=db,
            campaign_id=sbi_camp.id,
            analysis_id="demo-sbi-2",
            url="https://sbi-update-kyc.com",
            domain="sbi-update-kyc.com",
            status="Critical",
            threat_score=94,
            website_identity="SBI NetBanking",
            attack_type="KYC & Identity Theft",
            reason="This website captures sensitive financial records pretending to update SBI KYC.",
            information_at_risk=["Bank Account", "Debit Card", "CVV", "OTP"],
            why_blocked=["Deceptive KYC harvesting page"],
            recommended_action="Contact official SBI customer support."
        )
        CampaignRepository.increment_campaign_occurrence(db, sbi_camp.id)

        # 2. PayPal Campaign
        pp_camp = CampaignRepository.create_campaign(
            db=db,
            name="PayPal Credential Theft Campaign",
            target_brand="PayPal",
            attack_type="Account Hijacking",
            threat_level="Critical"
        )
        t3 = ThreatRepository.create_threat_record(
            db=db,
            campaign_id=pp_camp.id,
            analysis_id="demo-paypal-1",
            url="https://paypal-verify-alert.com",
            domain="paypal-verify-alert.com",
            status="Critical",
            threat_score=92,
            website_identity="PayPal",
            attack_type="Account Hijacking",
            reason="This site clones PayPal login screens to capture payment credentials.",
            information_at_risk=["Email", "Password", "Credit Card", "CVV"],
            why_blocked=["Cloned login portal", "Known malicious domain"],
            recommended_action="Log in only through paypal.com."
        )
        EvidenceRepository.create_evidence(
            db=db,
            threat_id=t3.id,
            ai_summary="This phishing campaign clones PayPal authentication portals to harvest payment credentials.",
            reason=t3.reason,
            why_blocked=["Cloned login portal", "Known malicious domain"],
            information_at_risk=["Email", "Password", "Credit Card", "CVV"]
        )

        print("[Vigilo] Demo seeding completed successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    seed_demo_data()
