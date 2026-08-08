from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS

CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "authentication", "secure", "password", "otp",
    "2fa", "account", "identity", "wallet", "payment", "kyc", "bank", "update", "portal"
]

class Rule09CredentialKeywords(BaseRule):
    rule_id = "RULE_09"
    rule_name = "Credential Harvesting Keywords"
    category = "Keyword Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        full_url = payload.get("normalized_url", "").lower()
        
        # Check if the domain is a verified official brand domain
        is_official = any(registered_domain in official_list for official_list in OFFICIAL_BRAND_DOMAINS.values())

        if is_official:
            # Bypass generic keyword triggers on verified official brand platforms
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence="Keywords bypassed on verified official brand domain.",
                severity="INFO",
                category=self.category
            )

        matched_kws = [kw for kw in CREDENTIAL_KEYWORDS if kw in full_url]

        if matched_kws:
            weight = 20 if any(k in ["login", "signin", "password", "otp", "2fa", "kyc"] for k in matched_kws) else 15
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=weight,
                evidence=f"Matched credential collection terms: {matched_kws}",
                severity="HIGH" if weight >= 20 else "MEDIUM",
                category=self.category,
                details={"matched_keywords": matched_kws}
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="No credential keywords detected",
            severity="INFO",
            category=self.category
        )
