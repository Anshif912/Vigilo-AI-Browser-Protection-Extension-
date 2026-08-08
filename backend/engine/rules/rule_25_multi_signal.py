from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule25MultiSignalRequirement(BaseRule):
    rule_id = "RULE_25"
    rule_name = "Multi-Signal Evidence Alignment Gate"
    category = "Scoring Orchestration"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        # Orchestration happens inside fusion_engine, this rule logs telemetry
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="Gate validated at final decision layer.",
            severity="INFO",
            category=self.category
        )
