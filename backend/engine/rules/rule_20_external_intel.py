from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.external_intel_service import ExternalIntelService

class Rule20ExternalIntel(BaseRule):
    rule_id = "RULE_20"
    rule_name = "External Threat Intelligence Federation"
    category = "Threat Intelligence"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        url = payload.get("normalized_url") or payload.get("raw_url", "")
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "")

        try:
            intel = ExternalIntelService.check_url(url, registered_domain)
            is_flagged = intel.get("overall_flagged", False)
            match_source = intel.get("matched_source")

            if is_flagged:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=35,
                    evidence=f"Flagged active malicious URL in threat feed ({match_source})",
                    severity="CRITICAL",
                    category=self.category,
                    details=intel
                )
            
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence="URL clear across external threat intelligence feeds",
                severity="INFO",
                category=self.category,
                details=intel
            )
        except Exception:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "External threat intel check bypassed (offline)", "INFO", self.category)
