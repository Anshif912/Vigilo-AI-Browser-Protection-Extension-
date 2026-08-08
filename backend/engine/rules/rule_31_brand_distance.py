from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

class Rule31BrandDomainDistance(BaseRule):
    rule_id = "RULE_31"
    rule_name = "Brand Domain Edit Distance (Typosquatting Check)"
    category = "Brand Intelligence"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()

        if not registered_domain:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence="No registered domain to check edit distance.",
                severity="INFO",
                category=self.category
            )

        domain_parts = registered_domain.split('.')
        domain_name = domain_parts[0] if domain_parts else registered_domain

        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            for official in official_domains:
                official_parts = official.split('.')
                official_name = official_parts[0] if official_parts else official

                # Skip exact matches
                if domain_name == official_name:
                    continue

                # Calculate edit distance
                dist = levenshtein_distance(domain_name, official_name)
                
                # Distance 1 implies high probability of typosquatting
                if dist == 1 and len(official_name) >= 4:
                    return RuleResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        matched=True,
                        weight=30,
                        evidence=f"Typosquatting check failed: Domain '{registered_domain}' differs from official brand domain '{official}' by Levenshtein edit distance of 1.",
                        severity="HIGH",
                        category=self.category,
                        details={"target_brand": brand, "official_domain": official, "distance": 1}
                    )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="Domain passed brand edit distance check.",
            severity="INFO",
            category=self.category
        )
