import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS, ALL_BRAND_ENTRIES

def get_clean_query_params(query_string: str) -> Dict[str, str]:
    """
    Parses a query string, filtering out standard marketing/tracking parameters.
    """
    if not query_string:
        return {}
    try:
        params = urllib.parse.parse_qsl(query_string)
        ignored_keys = {"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "ref", "source", "campaign", "gclid", "fbclid"}
        return {k.lower(): v.lower() for k, v in params if k.lower() not in ignored_keys}
    except Exception:
        return {}

class Rule08QueryAbuse(BaseRule):
    rule_id = "RULE_08"
    rule_name = "Query Parameter Brand Abuse"
    category = "Brand Impersonation"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()
        query = psl.get("query", "").lower()

        if not query:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No query parameters present", "INFO", self.category)

        clean_params = get_clean_query_params(query)
        if not clean_params:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No non-tracking query parameters present", "INFO", self.category)

        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 3:
                continue

            official_domains = OFFICIAL_BRAND_DOMAINS.get(brand, [])
            if registered_domain in official_domains:
                continue  # Bypassed on official brand platforms

            # Check if brand exists in the values of any clean query parameters
            for k, v in clean_params.items():
                if brand in v and brand not in registered_domain and brand not in subdomain:
                    # Deceptive context check: is it in a redirect/url param?
                    is_deceptive_param = k in {"redirect", "url", "goto", "dest", "next", "return", "to"} or v.startswith("http")
                    
                    if is_deceptive_param:
                        brand_label = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                        return RuleResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            matched=True,
                            weight=20,
                            evidence=f"Deceptive query parameter abuse: Trusted brand '{brand_label}' referenced in redirect/destination query param ({k}={v}) on unrelated domain '{registered_domain}'.",
                            warning=True,
                            severity="MEDIUM",
                            category=self.category,
                            details={"brand": brand_label, "param_key": k, "param_value": v}
                        )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No query parameter brand abuse", "INFO", self.category)
