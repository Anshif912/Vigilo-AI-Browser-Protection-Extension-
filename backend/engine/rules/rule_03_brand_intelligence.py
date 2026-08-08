import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import ALL_BRAND_ENTRIES, get_brand_category

def clean_query_string(query_string: str) -> str:
    """
    Strips standard marketing and tracking parameters from a query string before brand checks.
    """
    if not query_string:
        return ""
    try:
        params = urllib.parse.parse_qsl(query_string)
        ignored_keys = {"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "ref", "source", "campaign", "gclid", "fbclid"}
        filtered = [f"{k}={v}" for k, v in params if k.lower() not in ignored_keys]
        return "&".join(filtered)
    except Exception:
        return query_string

class Rule03BrandIntelligence(BaseRule):
    rule_id = "RULE_03"
    rule_name = "Brand Intelligence Knowledge Base Search"
    category = "Brand Intelligence"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()
        path = psl.get("path", "").lower()
        query = psl.get("query", "").lower()

        detected_brand = None
        detected_location = None
        matched = False

        cleaned_query = clean_query_string(query)

        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 3:
                continue

            if brand in registered_domain:
                detected_brand = brand
                detected_location = "registered_domain"
                matched = True
                break
            elif brand in subdomain:
                detected_brand = brand
                detected_location = "subdomain"
                matched = True
                break
            elif brand in path:
                detected_brand = brand
                detected_location = "path"
                matched = True
                break
            elif cleaned_query and brand in cleaned_query:
                detected_brand = brand
                detected_location = "query"
                matched = True
                break

        if matched and detected_brand:
            brand_label = detected_brand.upper() if detected_brand in ["sbi", "hdfc", "icici", "ibm"] else (
                "American Express" if detected_brand in ["americanexpress", "amex"] else detected_brand.capitalize()
            )
            brand_cat = get_brand_category(detected_brand)
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=30 if detected_location in ["registered_domain", "subdomain"] else 20,
                evidence=f"Brand '{brand_label}' detected inside {detected_location} (Category: {brand_cat})",
                severity="HIGH" if detected_location != "registered_domain" else "INFO",
                category=self.category,
                details={
                    "brand": brand_label,
                    "location": detected_location,
                    "category": brand_cat
                }
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="No enterprise brand target detected",
            severity="INFO",
            category=self.category,
            details={}
        )
