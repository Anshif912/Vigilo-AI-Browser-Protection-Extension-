from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import ALL_BRAND_ENTRIES

class Rule06SubdomainImpersonation(BaseRule):
    rule_id = "RULE_06"
    rule_name = "Subdomain Brand Impersonation"
    category = "Brand Impersonation"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()

        if not subdomain:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No subdomain present", "INFO", self.category)

        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 3:
                continue

            if brand in subdomain and brand not in registered_domain:
                brand_label = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=30,
                    evidence=f"Impersonating official identity of {brand_label} in subdomain structure ({subdomain})",
                    severity="HIGH",
                    category=self.category,
                    details={"brand": brand_label, "subdomain": subdomain}
                )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No subdomain brand impersonation", "INFO", self.category)
