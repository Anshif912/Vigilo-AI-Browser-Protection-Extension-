"""
Vigilo v3.5 - AI Threat Story Engine (Backend Parity Service)
Generates simple, human-friendly 120-180 word threat stories without technical jargon.
"""
from typing import Dict, Any, List, Optional
import time

JARGON_REPLACEMENTS = {
    "DOM": "web page structure",
    "IOC": "threat indicators",
    "Entropy": "randomness",
    "PSL": "domain registry",
    "Regex": "pattern matching",
    "HTML Injection": "page manipulation",
    "JavaScript Redirect": "automatic web page redirection"
}

class ThreatStoryEngineBackend:
    @staticmethod
    def generate_story(analysis: Dict[str, Any], lang: str = "en") -> Optional[Dict[str, Any]]:
        status = str(analysis.get("status", "")).lower()
        score = analysis.get("threat_score", 0)

        # Never show for Safe or Low Risk websites
        if status in ["safe", "low risk"] or (score < 40 and status not in ["suspicious", "critical", "high risk"]):
            return None

        start_time = time.perf_counter()

        brand = analysis.get("website_identity") or analysis.get("targetBrand") or "a trusted official service"
        category = analysis.get("category") or analysis.get("attack_type") or "Credential Phishing"

        info_str = " ".join(analysis.get("information_at_risk") or []).lower()
        reason_str = str(analysis.get("reason", "")).lower()
        cat_str = category.lower()

        stolen_items: List[str] = []
        if "password" in info_str or "login" in reason_str or "phishing" in cat_str:
            stolen_items.append("🔑 Passwords")
        if "email" in info_str or "mail" in reason_str or "account" in info_str:
            stolen_items.append("📧 Email Account")
        if "card" in info_str or "bank" in info_str or "payment" in reason_str:
            stolen_items.append("💳 Payment Information")
        if "wallet" in info_str or "crypto" in info_str or "crypto" in reason_str:
            stolen_items.append("🪙 Crypto Wallet")
        if not stolen_items or "identity" in info_str or "personal" in info_str:
            stolen_items.append("🪪 Personal Information")

        detection_reasons: List[str] = []
        if "browser security warning" in reason_str or "cloudflare" in reason_str or "reported" in reason_str:
            detection_reasons.append("Upstream security providers and browser warning systems have reported this page as deceptive.")
        if "typosquat" in reason_str or "brand" in reason_str or "impersonat" in reason_str:
            detection_reasons.append(f"The web address uses a fake or misspelled name designed to look like {brand}.")
        if "disposable" in reason_str or "free host" in reason_str or "subdomain" in reason_str:
            detection_reasons.append("The website is hosted on an unverified free cloud platform commonly used to disguise fake pages.")
        if "http" in reason_str or analysis.get("connection_security") == "Not Secure":
            detection_reasons.append("The web connection is unsecured, exposing your personal details to potential interception.")
        if not detection_reasons:
            detection_reasons.append("The web page structure matches patterns commonly associated with unauthorized login forms.")

        consequences = ["unauthorized access to your personal online accounts"]
        if "💳 Payment Information" in stolen_items or "🪙 Crypto Wallet" in stolen_items:
            consequences.append("financial loss or unauthorized bank transactions")

        stolen_text = " and ".join([i.split()[-1] for i in stolen_items])
        reason_text = " ".join(detection_reasons)
        consequence_text = " or ".join(consequences)

        story_text = (
            f"This website is pretending to be {brand}. It asks visitors to enter sensitive details including their {stolen_text}. "
            f"If you continue, your credentials could be sent to an unauthorized attacker instead of the official {brand} service. "
            f"{reason_text} Continuing on this page could lead to {consequence_text}. To protect your security and privacy, Vigilo "
            f"automatically blocked the page before any sensitive information could be transmitted."
        )

        for jargon, replacement in JARGON_REPLACEMENTS.items():
            story_text = story_text.replace(jargon, replacement)

        end_time = time.perf_counter()
        gen_time_ms = round((end_time - start_time) * 1000, 2)

        return {
            "title": "🧠 Threat Story",
            "story_text": story_text,
            "potential_impact": stolen_items,
            "confidence": analysis.get("confidence") or (96 if score >= 80 else 91),
            "generation_time_ms": gen_time_ms
        }
