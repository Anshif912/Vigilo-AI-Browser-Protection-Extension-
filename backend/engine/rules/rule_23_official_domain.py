from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS

class Rule23OfficialDomainValidation(BaseRule):
    rule_id = "RULE_23"
    rule_name = "Official Domain Identity Validation"
    category = "Legitimacy Verification"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        
        # Check if matches any official brand
        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            if registered_domain in official_domains:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=-40,  # Negative threat contribution (suppresses false score additions)
                    evidence=f"Verified official domain for recognized brand '{brand.capitalize()}'.",
                    severity="INFO",
                    category=self.category,
                    details={"brand": brand, "official_domain": registered_domain}
                )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="Not a registered official brand domain",
            severity="INFO",
            category=self.category
        )
