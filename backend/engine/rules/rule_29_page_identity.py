from typing import Dict, Any
from services.brand_database import ALL_BRAND_ENTRIES, OFFICIAL_BRAND_DOMAINS
from engine.base_rule import BaseRule, RuleResult

class Rule29PageIdentityConsistency(BaseRule):
    rule_id = "RULE_29"
    rule_name = "Page Identity & Visual Target Consistency check"
    category = "Content"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        dom_title = (payload.get("dom_title") or "").lower()
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()

        if not dom_title:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence="No page title metadata available.",
                severity="INFO",
                category=self.category
            )

        for brand in ALL_BRAND_ENTRIES:
            official_domains = OFFICIAL_BRAND_DOMAINS.get(brand, [])
            if not official_domains:
                continue

            # Brand name appears in title but registered domain does NOT match any of its official domains
            if brand in dom_title and registered_domain not in official_domains:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=35,
                    evidence=f"Deceptive identity mismatch: Page title claims brand target '{brand.capitalize()}', but domain '{registered_domain}' is unrelated.",
                    severity="HIGH",
                    category=self.category,
                    details={"brand": brand, "title": dom_title, "domain": registered_domain}
                )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="Page title matches domain identity attributes.",
            severity="INFO",
            category=self.category
        )
