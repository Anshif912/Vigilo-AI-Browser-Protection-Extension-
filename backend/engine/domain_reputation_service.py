from typing import Dict, Any

# Known High-Risk TLDs & Malicious Infrastructure Patterns
HIGH_RISK_TLD_SET = {
    "xyz", "top", "zip", "mov", "kim", "work", "cfd", "sbs", "cc", "fit", "surf",
    "country", "gq", "ml", "cf", "tk", "ga", "buzz", "rest", "cam", "icu", "monster"
}

FREE_HOSTING_PATTERNS = [
    "repl.co", "workers.dev", "pages.dev", "godaddysites.com", "webflow.io",
    "atwebpages.com", "duckdns.org", "hopto.org", "serveo.net", "byethost7.com"
]

class DomainReputationService:
    @staticmethod
    def evaluate_reputation(registered_domain: str, hostname: str, tld: str) -> Dict[str, Any]:
        """
        Evaluates domain infrastructure reputation, TLD risk, and hosting tier.
        """
        reg_lower = registered_domain.lower() if registered_domain else ""
        host_lower = hostname.lower() if hostname else ""
        tld_lower = tld.lower() if tld else ""

        reputation_score = 0
        reputation_status = "Clean Reputation"
        signals = []

        if tld_lower in HIGH_RISK_TLD_SET:
            reputation_score += 25
            signals.append(f"High-risk top-level domain '.{tld_lower}' commonly abused in phishing.")

        is_free_host = any(pattern in host_lower for pattern in FREE_HOSTING_PATTERNS)
        if is_free_host:
            reputation_score += 30
            signals.append("Abused free cloud hosting / dynamic DNS infrastructure platform.")

        if len(host_lower.split('.')) >= 4:
            reputation_score += 15
            signals.append("Deeply nested subdomain hierarchy (botnet/phishing structure pattern).")

        if reputation_score >= 35:
            reputation_status = "High Risk Reputation"
        elif reputation_score >= 15:
            reputation_status = "Suspicious Reputation"

        return {
            "reputation_status": reputation_status,
            "reputation_score": reputation_score,
            "is_free_hosting": is_free_host,
            "is_high_risk_tld": tld_lower in HIGH_RISK_TLD_SET,
            "signals": signals
        }
