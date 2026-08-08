import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

STANDARD_PORTS = {80, 443}

class Rule15NonStandardPorts(BaseRule):
    rule_id = "RULE_15"
    rule_name = "Non-Standard High-Risk Port Detection"
    category = "Structural Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        url = payload.get("normalized_url", "")
        
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
            port = parsed.port
        except Exception:
            port = None

        if port and port not in STANDARD_PORTS:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=15,
                evidence=f"URL specifies non-standard network port :{port}",
                severity="MEDIUM",
                category=self.category,
                details={"port": port}
            )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "Standard web port", "INFO", self.category)
