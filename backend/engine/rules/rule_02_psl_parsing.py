import urllib.parse
import tldextract
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule02PSLParsing(BaseRule):
    rule_id = "RULE_02"
    rule_name = "Public Suffix List Parsing"
    category = "Domain Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        url = payload.get("normalized_url") or payload.get("raw_url", "")
        
        try:
            parsed_url = urllib.parse.urlparse(url if "://" in url else "https://" + url)
            netloc = parsed_url.netloc or parsed_url.path.split("/")[0]
            hostname = netloc.split(":")[0].lower()
            path = parsed_url.path or "/"
            query = parsed_url.query or ""
        except Exception:
            hostname = url.split("/")[0].split(":")[0].lower()
            path = "/"
            query = ""

        extracted = tldextract.extract(url)
        registered_domain = extracted.registered_domain.lower() if extracted.registered_domain else hostname
        subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
        tld = extracted.suffix.lower() if extracted.suffix else ""
        domain = extracted.domain.lower() if extracted.domain else hostname

        details = {
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "domain": domain,
            "hostname": hostname,
            "tld": tld,
            "path": path,
            "query": query
        }

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=True,
            weight=0,
            evidence=f"Registered domain '{registered_domain}' (Subdomain: '{subdomain}', TLD: '.{tld}')",
            severity="INFO",
            category=self.category,
            details=details
        )
