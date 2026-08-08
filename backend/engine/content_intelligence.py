import re
from typing import Dict, Any, List
from services.brand_database import ALL_BRAND_ENTRIES

class ContentIntelligenceEngine:
    @staticmethod
    def analyze_content(dom_title: str = None, dom_text: str = None, registered_domain: str = "") -> Dict[str, Any]:
        title = (dom_title or "").lower()
        text = (dom_text or "").lower()
        full_content = f"{title} {text}"
        domain_lower = (registered_domain or "").lower()

        signals = []
        threat_score = 0
        detected_category = "General Content"
        detected_brand_impersonation = None
        has_fake_captcha = False
        has_malware_download = False
        has_credential_form = False
        has_financial_form = False

        # 1. Fake CAPTCHA / PowerShell Execution Lure Detection
        fake_captcha_patterns = [
            "press windows + r", "press win+r", "paste this command", "open powershell",
            "run this command", "copy and paste", "verify you are human", "robot verification",
            "ctrl+v", "powershell -e", "cmd.exe /c"
        ]
        if any(p in full_content for p in fake_captcha_patterns):
            has_fake_captcha = True
            threat_score += 55
            detected_category = "Social Engineering"
            signals.append("Fake CAPTCHA / PowerShell Execution Lure detected in page content.")

        # 2. Visual Brand Impersonation in Page Title or Headings
        for brand in ALL_BRAND_ENTRIES:
            if len(brand) >= 4 and brand in title and brand not in domain_lower:
                threat_score += 40
                detected_brand_impersonation = brand.capitalize()
                signals.append(f"Visual Brand Impersonation: Page title claims identity '{detected_brand_impersonation}' on unrelated domain '{domain_lower}'.")
                break

        # 3. Credential & Financial Form Indicators
        cred_terms = ["password", "enter password", "verify account", "account suspended", "sign in to continue", "login to your account", "confirm identity"]
        financial_terms = ["otp", "cvv", "credit card", "card number", "upi pin", "bank account", "wallet seed", "private key"]

        if any(term in full_content for term in cred_terms):
            has_credential_form = True
            threat_score += 20
            signals.append("Credential harvesting input fields detected in page content.")

        if any(term in full_content for term in financial_terms):
            has_financial_form = True
            threat_score += 30
            signals.append("Sensitive payment or financial OTP input fields detected.")

        # 4. Malware Download Payload Extensions
        malware_exts = [".exe", ".msi", ".ps1", ".vbs", ".iso", ".bat", ".cmd", ".scr"]
        if any(ext in full_content for ext in malware_exts):
            has_malware_download = True
            threat_score += 35
            signals.append("Executable malware payload download links detected.")

        return {
            "threat_score": min(threat_score, 85),
            "detected_category": detected_category,
            "detected_brand_impersonation": detected_brand_impersonation,
            "has_fake_captcha": has_fake_captcha,
            "has_malware_download": has_malware_download,
            "has_credential_form": has_credential_form,
            "has_financial_form": has_financial_form,
            "signals": signals
        }
