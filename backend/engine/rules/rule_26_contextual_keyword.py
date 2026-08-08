import urllib.parse
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import OFFICIAL_BRAND_DOMAINS

SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "support", "account", "billing", "signin", "auth", "checkout"}

class Rule26ContextualKeywordAnalysis(BaseRule):
    rule_id = "RULE_26"
    rule_name = "Context-Aware URL Keyword Analysis"
    category = "URL Semantics"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        raw_url = payload.get("raw_url", "").lower()
        
        parsed = urllib.parse.urlparse(raw_url)
        path = parsed.path
        query = parsed.query

        # Check if keyword is in the domain itself (which is suspicious for non-official sites)
        matched_domain_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in registered_domain]
        
        # Check if this domain is official for any recognized brand
        is_official = any(registered_domain in official_list for official_list in OFFICIAL_BRAND_DOMAINS.values())

        if is_official:
            # Bypass keyword check for official domains (e.g. github.com/login is legitimate)
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=False,
                weight=0,
                evidence="Keywords bypassed on verified official brand domain.",
                severity="INFO",
                category=self.category
            )

        if matched_domain_kw:
            # Keyword in registered domain of non-official site (e.g. secure-paypal-login.xyz)
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=20,
                evidence=f"Suspicious keyword(s) {matched_domain_kw} inside registered domain of non-official website.",
                severity="MEDIUM",
                category=self.category,
                details={"keywords": matched_domain_kw, "location": "domain"}
            )

        # Keyword in path/query is generic, give minor score contribution
        matched_path_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query]
        if matched_path_kw:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=5,
                evidence=f"Keyword(s) {matched_path_kw} present in URL path or query params.",
                severity="LOW",
                category=self.category,
                details={"keywords": matched_path_kw, "location": "path/query"}
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="No suspicious keywords detected in domain, path or query",
            severity="INFO",
            category=self.category
        )
