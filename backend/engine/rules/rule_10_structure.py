from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule10Structure(BaseRule):
    rule_id = "RULE_10"
    rule_name = "High-Risk Obfuscated URL Structure"
    category = "Structural Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        full_url = payload.get("normalized_url", "")
        psl = payload.get("psl", {})
        hostname = psl.get("hostname", "")
        path = psl.get("path", "")

        anomalies = []
        weight = 0

        # Long hostname
        if len(hostname) > 28:
            anomalies.append(f"Hostname length ({len(hostname)} chars) exceeds 28 threshold")
            weight += 5

        # Hyphen abuse in hostname
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            anomalies.append(f"Excessive hyphen separators ({hyphen_count} hyphens)")
            weight += 10

        # Subdomain nesting depth
        subdomain = psl.get("subdomain", "")
        if subdomain and subdomain.count(".") >= 2:
            anomalies.append(f"Deep subdomain nesting level ({subdomain.count('.') + 1} levels)")
            weight += 10

        # Deep folder nesting
        folder_depth = path.count("/")
        if folder_depth >= 4:
            anomalies.append(f"Deep directory folder nesting ({folder_depth} levels)")
            weight += 5

        matched = len(anomalies) > 0
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            weight=min(weight, 15),
            evidence="; ".join(anomalies) if matched else "Normal URL structure",
            severity="MEDIUM" if weight >= 10 else "INFO",
            category=self.category,
            details={"anomalies": anomalies}
        )
