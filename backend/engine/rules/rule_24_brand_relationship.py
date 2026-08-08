import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS, ALL_BRAND_ENTRIES

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

class Rule24BrandRelationship(BaseRule):
    rule_id = "RULE_24"
    rule_name = "Brand Relationship Taxonomy Analysis"
    category = "Brand Intelligence"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        subdomain = psl.get("subdomain", "").lower()
        raw_url = payload.get("raw_url", "").lower()
        
        parsed = urllib.parse.urlparse(raw_url)
        path = parsed.path
        query = parsed.query

        # Check brand references
        for brand in ALL_BRAND_ENTRIES:
            official_domains = OFFICIAL_BRAND_DOMAINS.get(brand, [])

            # Case 1: Official Domain Match
            if registered_domain in official_domains:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=0,
                    evidence=f"Brand '{brand.capitalize()}' matches verified official domain: {registered_domain}",
                    severity="INFO",
                    category=self.category,
                    details={"brand": brand, "relationship": "OFFICIAL"}
                )

            # Case 2: Subdomain Impersonation (e.g. google.com.example.org)
            if brand in subdomain and registered_domain not in official_domains:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=30,
                    evidence=f"Deceptive subdomain impersonation of brand '{brand.capitalize()}' on unrelated domain '{registered_domain}'.",
                    severity="HIGH",
                    category=self.category,
                    details={"brand": brand, "relationship": "SUBDOMAIN_IMPERSONATION"}
                )

            # Case 3: Path Reference (e.g. evil.xyz/google/login)
            if brand in path:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=15,
                    evidence=f"Brand reference '{brand.capitalize()}' in path on unrelated domain '{registered_domain}'.",
                    severity="MEDIUM",
                    category=self.category,
                    details={"brand": brand, "relationship": "PATH_REFERENCE"}
                )

            # Case 4: Query Reference (e.g. evil.xyz?redirect=google.com)
            cleaned_query = clean_query_string(query)
            if cleaned_query and brand in cleaned_query:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=10,
                    evidence=f"Brand reference '{brand.capitalize()}' in query params on unrelated domain '{registered_domain}'.",
                    severity="MEDIUM",
                    category=self.category,
                    details={"brand": brand, "relationship": "QUERY_REFERENCE"}
                )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="No brand relationship detected",
            severity="INFO",
            category=self.category
        )
