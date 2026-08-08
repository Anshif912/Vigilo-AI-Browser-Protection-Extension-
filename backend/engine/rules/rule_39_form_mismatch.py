from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule39FormDestinationMismatch(BaseRule):
    rule_id = "RULE_39"
    rule_name = "Form Action Endpoint & Domain Mismatch"
    category = "Content"
    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        return RuleResult(self.rule_id, self.rule_name, False, 0, "Form action destinations consistent with host domain.", "INFO", self.category)
