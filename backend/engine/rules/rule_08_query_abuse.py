from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import ALL_BRAND_ENTRIES

class Rule08QueryAbuse(BaseRule):
    rule_id = "RULE_08"
    rule_name = "Query Parameter Brand Abuse"
    category = "Brand Impersonation"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()
        query = psl.get("query", "").lower()

        if not query:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No query parameters present", "INFO", self.category)

        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 3:
                continue

            if brand in query and brand not in registered_domain and brand not in subdomain:
                brand_label = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=20,
                    evidence=f"Trusted brand '{brand_label}' referenced in query parameter string ({query})",
                    severity="MEDIUM",
                    category=self.category,
                    details={"brand": brand_label, "query": query}
                )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No query parameter brand abuse", "INFO", self.category)
