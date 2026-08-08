import re
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule18DOMForms(BaseRule):
    rule_id = "RULE_18"
    rule_name = "Credential & Payment Form DOM Inspection"
    category = "Credential Harvesting"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        html = payload.get("html_content")
        if not html:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No HTML DOM payload provided", "INFO", self.category)

        html_lower = html.lower()
        evidence_items = []
        weight = 0

        if 'type="password"' in html_lower or "type='password'" in html_lower:
            evidence_items.append("Password Input Field")
            weight += 20

        if any(term in html_lower for term in ["cardnumber", "card_number", "cvv", "creditcard", "expdate"]):
            evidence_items.append("Credit Card / Financial Input Form")
            weight += 25

        if any(term in html_lower for term in ["otp", "one time password", "2fa", "authenticator"]):
            evidence_items.append("Two-Factor OTP Verification Form")
            weight += 15

        if any(term in html_lower for term in ["seed phrase", "recovery phrase", "private key"]):
            evidence_items.append("Crypto Wallet Seed Phrase Form")
            weight += 30

        matched = len(evidence_items) > 0
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            weight=min(weight, 30),
            evidence=f"DOM contains sensitive fields: {', '.join(evidence_items)}" if matched else "No sensitive DOM input fields detected",
            severity="CRITICAL" if weight >= 25 else ("HIGH" if matched else "INFO"),
            category=self.category,
            details={"sensitive_elements": evidence_items}
        )
