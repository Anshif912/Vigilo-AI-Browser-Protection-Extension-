from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule27DomainAgeReputation(BaseRule):
    rule_id = "RULE_27"
    rule_name = "Domain Infrastructure Age & Reputation Signal"
    category = "Reputation"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        # Since domain age details are fetched asynchronously, we default to neutral.
        # Unknown/Lack of domain age info must NOT mean malicious.
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="Domain age telemetry unavailable (treated as neutral).",
            severity="INFO",
            category=self.category
        )
