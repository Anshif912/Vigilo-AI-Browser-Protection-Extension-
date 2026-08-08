import re
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import ALL_BRAND_ENTRIES

L33T_MAP = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b'}

class Rule12NumericAbuse(BaseRule):
    rule_id = "RULE_12"
    rule_name = "Numeric Substitution & L33tspeak Abuse"
    category = "Numeric Abuse"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        domain = psl.get("domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()
        target = f"{subdomain}.{domain}" if subdomain else domain

        # Check if digits replace letters in brand patterns
        if any(char.isdigit() for char in target):
            normalized = target
            for num, letter in L33T_MAP.items():
                normalized = normalized.replace(num, letter)

            for brand in ALL_BRAND_ENTRIES:
                if len(brand) < 4:
                    continue
                if brand in normalized and brand not in target:
                    brand_label = brand.capitalize()
                    return RuleResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        matched=True,
                        weight=25,
                        evidence=f"Numeric l33tspeak substitution abusing brand '{brand_label}' in hostname ({target})",
                        severity="HIGH",
                        category=self.category,
                        details={"brand": brand_label, "original": target, "normalized": normalized}
                    )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No numeric l33tspeak substitution detected", "INFO", self.category)
