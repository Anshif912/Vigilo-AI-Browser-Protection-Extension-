from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "authentication", "secure", "password", "otp",
    "2fa", "account", "identity", "wallet", "payment", "kyc", "bank", "update", "portal"
]

class Rule09CredentialKeywords(BaseRule):
    rule_id = "RULE_09"
    rule_name = "Credential Harvesting Keywords"
    category = "Keyword Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        full_url = payload.get("normalized_url", "").lower()
        
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

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No credential keywords detected", "INFO", self.category)
