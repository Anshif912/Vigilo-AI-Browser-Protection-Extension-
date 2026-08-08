from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule14UsernameTrick(BaseRule):
    rule_id = "RULE_14"
    rule_name = "URL Userinfo Authority Deception Trick"
    category = "Structural Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        raw_url = payload.get("raw_url", "")
        
        if "@" in raw_url:
            userinfo = raw_url.split("@")[0].replace("https://", "").replace("http://", "")
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=35,
                evidence=f"Deceptive userinfo authority string '@' embedding target brand before host ({userinfo})",
                severity="CRITICAL",
                category=self.category,
                details={"userinfo": userinfo}
            )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No userinfo '@' authority trick detected", "INFO", self.category)
