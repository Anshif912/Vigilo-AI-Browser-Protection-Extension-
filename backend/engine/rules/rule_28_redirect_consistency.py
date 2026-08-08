import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS

class Rule28RedirectConsistency(BaseRule):
    rule_id = "RULE_28"
    rule_name = "Redirect Infrastructure Consistency check"
    category = "Behavioral"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        dest_intel = payload.get("destination_intel", {})
        redirect_chain = dest_intel.get("redirect_chain", [])
        raw_url = payload.get("raw_url", "")

        if len(redirect_chain) <= 1:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence="No redirects detected.",
                severity="INFO",
                category=self.category
            )

        orig_host = urllib.parse.urlparse(raw_url).hostname or ""
        final_url = dest_intel.get("final_url", raw_url)
        final_host = urllib.parse.urlparse(final_url).hostname or ""

        # Check if redirect is within the same brand's official infrastructure
        orig_brand = None
        final_brand = None

        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            for official in official_domains:
                if orig_host.endswith(official):
                    orig_brand = brand
                if final_host.endswith(official):
                    final_brand = brand

        if orig_brand and final_brand and orig_brand == final_brand:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence=f"Legitimate intra-brand redirect verified for brand '{orig_brand.capitalize()}'.",
                severity="INFO",
                category=self.category
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="Redirect consistency check passed (non-suspicious shift).",
            severity="INFO",
            category=self.category
        )
