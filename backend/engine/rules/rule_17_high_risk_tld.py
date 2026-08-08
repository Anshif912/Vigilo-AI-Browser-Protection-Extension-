from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

HIGH_RISK_TLDS = {"xyz", "top", "click", "site", "online", "live", "store", "shop", "tech", "work", "loan", "club", "vip", "icu", "fit"}

class Rule17HighRiskTLD(BaseRule):
    rule_id = "RULE_17"
    rule_name = "High-Risk Top Level Domain (TLD) Analysis"
    category = "TLD Risk Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        tld = psl.get("tld", "").lower()

        if tld in HIGH_RISK_TLDS:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=15,
                evidence=f"Domain utilizes high-risk TLD '.{tld}' commonly abused in automated phishing campaigns",
                severity="MEDIUM",
                category=self.category,
                details={"tld": tld}
            )

        return RuleResult(self.rule_id, self.rule_name, False, 0, f"TLD '.{tld}' within baseline risk parameters", "INFO", self.category, {"tld": tld})
