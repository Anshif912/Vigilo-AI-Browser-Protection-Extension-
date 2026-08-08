from typing import Dict, Any, List
from services.brand_database import OFFICIAL_BRAND_DOMAINS

class LegitimacyEngine:
    @staticmethod
    def evaluate_legitimacy(payload: Dict[str, Any], matched_rules: List[Any]) -> Dict[str, Any]:
        """
        Calculates positive evidence of safety, brand domain consistency, and TLS integrity.
        """
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", "").lower()
        dest_intel = payload.get("destination_intel", {})
        
        is_official = False
        associated_brand = None
        
        # Determine if registered domain belongs to any official brand
        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            if registered_domain in official_domains:
                is_official = True
                associated_brand = brand
                break

        # Collect positive signals
        has_valid_tls = dest_intel.get("tls_valid", False) and dest_intel.get("scheme") == "https"
        has_reachable_dns = dest_intel.get("dns_status") == "RESOLVED"
        
        # Deception checks based on matched rules
        has_typosquatting = any(r.rule_id in ["RULE_04", "RULE_31"] for r in matched_rules)
        has_homograph = any(r.rule_id == "RULE_05" for r in matched_rules)
        has_suspicious_redirect = any(r.rule_id in ["RULE_22", "RULE_38"] for r in matched_rules)
        has_impersonation = any(r.rule_id in ["RULE_06", "RULE_07"] or (r.rule_id == "RULE_24" and r.weight > 0) for r in matched_rules)
        has_harvesting = any(r.rule_id in ["RULE_09", "RULE_18", "RULE_30"] for r in matched_rules)

        is_deceptive = has_typosquatting or has_homograph or has_suspicious_redirect or has_impersonation or has_harvesting

        legitimacy_signals = []
        is_legitimate = False

        if is_official:
            legitimacy_signals.append(f"Confirmed official registered domain for brand '{associated_brand.capitalize()}'")
            if has_valid_tls and has_reachable_dns and not is_deceptive:
                is_legitimate = True
                legitimacy_signals.append("Verified secure connection with valid TLS certificate authority.")

        # Generic legitimacy check for unknown (but benign) domains
        elif has_valid_tls and has_reachable_dns and not is_deceptive:
            # Clean structure check
            subdomain_count = len(psl.get("subdomain", "").split('.')) if psl.get("subdomain") else 0
            hyphen_count = registered_domain.count('-')
            
            if subdomain_count <= 2 and hyphen_count <= 1:
                is_legitimate = True
                legitimacy_signals.append("Domain exhibits normal structure and valid SSL encryption with no matched threat heuristics.")

        return {
            "is_legitimate": is_legitimate,
            "is_official": is_official,
            "associated_brand": associated_brand,
            "has_valid_tls": has_valid_tls,
            "has_reachable_dns": has_reachable_dns,
            "legitimacy_signals": legitimacy_signals
        }
