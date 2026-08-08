import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule22RedirectChainAnalysis(BaseRule):
    rule_id = "RULE_22"
    rule_name = "Redirect Chain & Protocol Downgrade"
    category = "Suspicious Redirect"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        dest_intel = payload.get("destination_intel", {})
        redirect_chain = dest_intel.get("redirect_chain", [])
        has_cross_domain = dest_intel.get("has_cross_domain_redirect", False)
        has_downgrade = dest_intel.get("has_protocol_downgrade", False)
        raw_url = payload.get("raw_url", "")

        if len(redirect_chain) <= 1 and not has_cross_domain and not has_downgrade:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No suspicious redirect chain detected", "INFO", self.category)

        weight = 0
        reasons = []

        if has_downgrade:
            weight += 35
            reasons.append("Secure HTTPS connection downgraded to unencrypted HTTP across redirect.")

        if has_cross_domain:
            weight += 25
            orig_host = urllib.parse.urlparse(raw_url).hostname or "initial domain"
            final_host = urllib.parse.urlparse(dest_intel.get("final_url", "")).hostname or "final domain"
            reasons.append(f"Cross-domain redirect detected from '{orig_host}' to '{final_host}'.")

        if len(redirect_chain) >= 3:
            weight += 20
            reasons.append(f"Excessive redirect chain detected ({len(redirect_chain)} redirect steps).")

        evidence_str = " | ".join(reasons)
        severity = "HIGH" if weight >= 35 else "MEDIUM"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=True,
            weight=weight,
            evidence=evidence_str,
            severity=severity,
            category=self.category,
            details={
                "redirect_chain": redirect_chain,
                "has_cross_domain": has_cross_domain,
                "has_downgrade": has_downgrade,
                "final_url": dest_intel.get("final_url", raw_url)
            }
        )
