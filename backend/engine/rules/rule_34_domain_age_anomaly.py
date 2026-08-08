from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule34DomainAgeAnomaly(BaseRule):
    rule_id = "RULE_34"
    rule_name = "Domain Age Anomaly check"
    category = "Infrastructure"
    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        return RuleResult(self.rule_id, self.rule_name, False, 0, "No domain age anomaly detected.", "INFO", self.category)
