import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS

class Rule38RedirectBrandShift(BaseRule):
    rule_id = "RULE_38"
    rule_name = "Redirect Chain Brand Target Shift check"
    category = "Behavioral"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        dest_intel = payload.get("destination_intel", {})
        redirect_chain = dest_intel.get("redirect_chain", [])
        raw_url = payload.get("raw_url", "")

        if len(redirect_chain) <= 1:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No brand shift detected in redirect.", "INFO", self.category)

        orig_host = urllib.parse.urlparse(raw_url).hostname or ""
        final_url = dest_intel.get("final_url", raw_url)
        final_host = urllib.parse.urlparse(final_url).hostname or ""

        # Check if redirect starts with an official domain and lands on unrelated domain
        orig_brand = None
        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            for official in official_domains:
                if orig_host.endswith(official):
                    orig_brand = brand
                    break
            if orig_brand:
                break

        if orig_brand:
            final_officials = OFFICIAL_BRAND_DOMAINS.get(orig_brand, [])
            # If final host doesn't end with any of the brand's official domains
            if final_officials and not any(final_host.endswith(fo) for fo in final_officials):
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=30,
                    evidence=f"Deceptive brand shift: Redirect starts on official '{orig_brand.capitalize()}' domain but lands on unrelated '{final_host}'.",
                    severity="HIGH",
                    category=self.category,
                    details={"brand": orig_brand, "final_host": final_host}
                )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No suspicious redirect brand shift detected.", "INFO", self.category)
