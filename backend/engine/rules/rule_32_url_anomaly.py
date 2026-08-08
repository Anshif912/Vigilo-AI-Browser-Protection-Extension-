from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule32UrlStructuralAnomaly(BaseRule):
    rule_id = "RULE_32"
    rule_name = "URL Structural Anomaly check"
    category = "Infrastructure"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        raw_url = payload.get("raw_url", "")
        psl = payload.get("psl", {})
        subdomain = psl.get("subdomain", "")
        registered_domain = psl.get("registered_domain", "")

        weight = 0
        reasons = []

        # Check subdomains
        if subdomain:
            subdomain_parts = subdomain.split('.')
            if len(subdomain_parts) >= 3:
                weight += 5
                reasons.append("Excessive subdomain nesting.")

        # Check hyphens
        hyphen_count = registered_domain.count('-')
        if hyphen_count >= 3:
            weight += 5
            reasons.append("Excessive hyphens in registered domain name.")

        # Check length
        if len(raw_url) > 150:
            weight += 5
            reasons.append("Abnormally long URL length.")

        if weight > 0:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=weight,
                evidence=" | ".join(reasons),
                severity="LOW",
                category=self.category,
                details={"reasons": reasons}
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="No structural anomalies detected.",
            severity="INFO",
            category=self.category
        )
