import math
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

def calculate_shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return round(entropy, 2)

class Rule11Entropy(BaseRule):
    rule_id = "RULE_11"
    rule_name = "Shannon Entropy & Randomness Analysis"
    category = "Entropy Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        hostname = psl.get("hostname", "")
        domain_name = psl.get("domain", "")

        entropy = calculate_shannon_entropy(domain_name or hostname)

        if entropy >= 3.80 and len(domain_name) >= 8:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=10,
                evidence=f"Domain randomness entropy ({entropy}) exceeds risk threshold (3.80)",
                severity="MEDIUM",
                category=self.category,
                details={"entropy": entropy}
            )

        return RuleResult(self.rule_id, self.rule_name, False, 0, f"Entropy ({entropy}) within normal range", "INFO", self.category, {"entropy": entropy})
