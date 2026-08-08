from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    matched: bool
    weight: int
    evidence: str
    severity: str  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    category: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "matched": self.matched,
            "weight": self.weight,
            "evidence": self.evidence,
            "severity": self.severity,
            "category": self.category,
            "details": self.details or {}
        }

class BaseRule:
    rule_id: str = "RULE_BASE"
    rule_name: str = "Base Rule"
    category: str = "General"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        raise NotImplementedError("Each detection rule must implement evaluate(payload)")
