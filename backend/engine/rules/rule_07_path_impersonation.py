from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import ALL_BRAND_ENTRIES

class Rule07PathImpersonation(BaseRule):
    rule_id = "RULE_07"
    rule_name = "Path Brand Impersonation"
    category = "Brand Impersonation"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()
        path = psl.get("path", "").lower()

        if not path or path == "/":
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No URL path present", "INFO", self.category)

        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 3:
                continue

            if brand in path and brand not in registered_domain and brand not in subdomain:
                if brand in ["americanexpress", "amex"]:
                    brand_label = "American Express"
                elif brand in ["sbi", "hdfc", "icici", "ibm"]:
                    brand_label = brand.upper()
                else:
                    brand_label = brand.capitalize()

                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=20,
                    evidence=f"Trusted brand '{brand_label}' detected inside URL path while registered domain is {registered_domain}.",
                    severity="HIGH",
                    category=self.category,
                    details={"brand": brand_label, "path": path, "registered_domain": registered_domain}
                )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No path brand impersonation", "INFO", self.category)
