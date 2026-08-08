from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule21BrowserSecurityInterstitial(BaseRule):
    """
    RULE 21 — BROWSER SECURITY INTERSTITIAL & UPSTREAM VENDOR WARNING DETECTION
    Detects when a page is an active security warning interstitial rendered by
    Cloudflare, Google Safe Browsing, Microsoft SmartScreen, Firefox, or Brave,
    or a disposable free hosting phishing endpoint (repl.co, workers.dev, ngrok, etc.).
    """
    rule_id = "RULE_21"
    rule_name = "Upstream Security Vendor Interstitial Detection"
    category = "Browser Security Warning"
    weight = 100
    severity = "CRITICAL"
    
    cloudflare_markers = [
        "suspected phishing", "potential phishing", "attention required!",
        "this website has been reported", "this website has been reported for potential phishing",
        "phishing site ahead", "cf-error-details", "cloudflare ray id", "cloud-flare",
        "phishing is when a site attempts to steal", "performance & security by cloudflare"
    ]
    
    google_safe_browsing_markers = [
        "deceptive site ahead", "dangerous site", "phishing attack ahead",
        "the site ahead contains malware", "malware ahead", "chromewebdata"
    ]
    
    smartscreen_markers = [
        "this site has been reported as unsafe", "microsoft defender smartscreen",
        "phishing threat blocked by smartscreen"
    ]
    
    firefox_markers = [
        "deceptive site ahead", "reported web forgery", "reported attack page"
    ]

    free_hosting_domains = [
        "repl.co", "replit.dev", "replit.app", "workers.dev", "pages.dev",
        "ngrok.io", "ngrok-free.app", "000webhostapp.com", "azurewebsites.net",
        "glitch.me", "firebaseapp.com", "web.app", "herokuapp.com", "weebly.com", "wixsite.com"
    ]

    connection_error_markers = [
        "this site can't be reached", "check if there is a typo",
        "dns_probe_finished_nxdomain", "err_name_not_resolved",
        "err_connection_refused", "err_timed_out", "err_address_unreachable"
    ]

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        url = (payload.get("raw_url") or payload.get("url") or "").lower()
        dom_title = (payload.get("dom_title") or "").lower()
        dom_text = (payload.get("dom_text") or "").lower()
        html_content = (payload.get("html_content") or "").lower()
        
        combined_text = f"{url} {dom_title} {dom_text} {html_content}"
        
        vendor_detected = None
        matched_marker = None
        
        # 1. Cloudflare Interstitial Search
        for marker in self.cloudflare_markers:
            if marker in combined_text:
                vendor_detected = "Cloudflare Security Interstitial"
                matched_marker = marker
                break

        # 1b. Special check for Cloudflare Workers warning
        if not vendor_detected and "workers.dev" in url:
            subdomain_part = url.split("workers.dev")[0]
            has_suspicious_subdomain = "0000" in subdomain_part or len(subdomain_part.split(".")) >= 3
            if has_suspicious_subdomain or any(term in combined_text for term in ["phishing", "warning", "suspected", "reported", "steal sensitive"]):
                vendor_detected = "Cloudflare Workers Phishing Warning"
                matched_marker = "workers.dev suspicious worker endpoint"

        # 1c. Free Disposable Hosting Abuse Search (repl.co, workers.dev, ngrok, etc.)
        if not vendor_detected:
            for domain in self.free_hosting_domains:
                if domain in url:
                    subdomain_part = url.split(domain)[0]
                    has_suspicious_pattern = any(p in subdomain_part for p in ["0000", "000", "111", "999", "-"]) or len(subdomain_part.split(".")) >= 3 or len(subdomain_part) > 12
                    has_error = any(m in combined_text for m in self.connection_error_markers)
                    if has_suspicious_pattern or has_error:
                        vendor_detected = f"Disposable Free Hosting Abuse ({domain})"
                        matched_marker = f"Free hosting {domain} suspicious subdomain pattern"
                        break

        # 1d. Connection Error / Unreachable Site Search
        if not vendor_detected:
            for marker in self.connection_error_markers:
                if marker in combined_text:
                    vendor_detected = "Unreachable Site / Connection Error"
                    matched_marker = marker
                    break
        
        # Free / Disposable hosting & Dynamic DNS providers abused for phishing campaigns
        DISPOSABLE_HOSTS = [
            "000webhostapp.com", "weebly.com", "weeblysite.com", "pages.dev", "workers.dev",
            "repl.co", "godaddysites.com", "atwebpages.com", "webflow.io", "netlify.app",
            "duckdns.org", "appdomain.cloud", "co.vu", "125mb.com", "byethost7.com", "serveo.net",
            "tonohost.com", "wcomhost.com", "c1.biz", "hopto.org", "mybluehost.me", "vercel.app"
        ]

        if not vendor_detected:
            host_lower = url.split("//")[-1].split("/")[0]
            if any(host in host_lower for host in DISPOSABLE_HOSTS):
                # Check if it has suspicious subdomains (e.g. 000 padding, excessive digits, brand keywords)
                subdomain = host_lower.split(".")[0]
                if (
                    subdomain.startswith("000") or 
                    len(subdomain) > 15 or 
                    any(char.isdigit() for char in subdomain) or
                    any(b in host_lower for b in ["outlook", "microsof", "coinbase", "sbcglobal", "bancogeneral", "ficohs", "yah100", "codashop", "micloud", "agreementmail", "login", "auth", "mediafirew"])
                ):
                    vendor_detected = "Disposable Free Hosting / Dynamic DNS Abuse"
                    matched_marker = f"suspicious subdomain on {host_lower}"

            # Check for zero-padded botnet subdomains or brand typosquatting in domain
            if (
                host_lower.startswith("0000") or 
                host_lower.startswith("0.0.0.0") or
                any(b in host_lower for b in ["mediafirew", "coinbase", "binance", "metamask", "paypal", "trustwallet"]) and any(c.isdigit() for c in host_lower.split(".")[0])
            ):
                vendor_detected = "Zero-padded or Brand Typosquat Phishing domain"
                matched_marker = host_lower
                
        # 2. Google Safe Browsing Search
        if not vendor_detected:
            for marker in self.google_safe_browsing_markers:
                if marker in combined_text:
                    vendor_detected = "Google Safe Browsing Interstitial"
                    matched_marker = marker
                    break
                    
        # 3. Microsoft SmartScreen Search
        if not vendor_detected:
            for marker in self.smartscreen_markers:
                if marker in combined_text:
                    vendor_detected = "Microsoft Defender SmartScreen Interstitial"
                    matched_marker = marker
                    break

        # 4. Firefox Search
        if not vendor_detected:
            for marker in self.firefox_markers:
                if marker in combined_text:
                    vendor_detected = "Firefox Security Warning"
                    matched_marker = marker
                    break

        if vendor_detected:
            is_disposable = "Disposable Free Hosting" in vendor_detected
            weight_val = 65 if is_disposable else 100
            status_sev = "HIGH" if is_disposable else "CRITICAL"
            category_val = "Disposable Phishing Infrastructure" if is_disposable else "Browser Security Warning"
            
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                matched=True,
                weight=weight_val,
                evidence=f"Upstream vendor / hosting warning detected: '{vendor_detected}' (matched marker: '{matched_marker}')",
                severity=status_sev,
                category=category_val,
                details={
                    "vendor": vendor_detected,
                    "matched_marker": matched_marker,
                    "is_interstitial": True,
                    "force_critical": True
                }
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=False,
            weight=0,
            evidence="No upstream browser security interstitials detected.",
            severity="INFO",
            category="Browser Security Warning"
        )
