import re
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

class Rule13IPAddress(BaseRule):
    rule_id = "RULE_13"
    rule_name = "IP Address Host URL Detection"
    category = "Structural Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        hostname = psl.get("hostname", "")

        is_ip = bool(IPV4_PATTERN.match(hostname)) or "[" in hostname

        if is_ip:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=30,
                evidence=f"URL utilizes raw IP address host '{hostname}' instead of registered domain name",
                severity="HIGH",
                category=self.category,
                details={"ip_host": hostname}
            )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "Host is domain name", "INFO", self.category)
