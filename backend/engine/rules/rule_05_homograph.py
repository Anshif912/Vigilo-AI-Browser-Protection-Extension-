from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

HOMOGRAPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm'
}

def normalize_homographs(text: str) -> str:
    res = text.lower()
    for k, v in HOMOGRAPH_MAP.items():
        res = res.replace(k, v)
    return res

class Rule05Homograph(BaseRule):
    rule_id = "RULE_05"
    rule_name = "Homograph & Punycode Character Detection"
    category = "Homograph Detection"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        raw_url = payload.get("raw_url", "")
        psl = payload.get("psl", {})
        hostname = psl.get("hostname", "").lower()

        is_punycode = "xn--" in hostname or "xn--" in raw_url
        contains_non_ascii = any(ord(c) > 127 for c in hostname)

        if is_punycode or contains_non_ascii:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=30,
                evidence=f"Internationalized Punycode/Unicode homograph string detected in hostname ({hostname})",
                severity="HIGH",
                category=self.category,
                details={"is_punycode": is_punycode, "contains_non_ascii": contains_non_ascii}
            )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No Punycode/Unicode homograph detected", "INFO", self.category)
