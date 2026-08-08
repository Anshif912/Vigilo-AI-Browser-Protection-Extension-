import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
import json
from services.url_analyzer import UniversalURLAnalyzer
from analyze_top_100 import top_100_urls

fn_list = []
for i, raw_url in enumerate(top_100_urls, 1):
    res = UniversalURLAnalyzer.analyze_url(raw_url)
    
    # Identify if raw_url has malicious indicator based on phishing heuristics:
    url_lower = raw_url.lower()
    is_malicious = False
    reasons = []
    
    # Phishing markers:
    if any(h in url_lower for h in [
        "000webhostapp.com", "weebly.com", "weeblysite.com", "pages.dev", "workers.dev",
        "repl.co", "godaddysites.com", "atwebpages.com", "webflow.io", "netlify.app",
        "duckdns.org", "appdomain.cloud", "co.vu", "125mb.com", "byethost7.com", "serveo.net",
        "tonohost.com", "wcomhost.com", "c1.biz"
    ]):
        is_malicious = True
        reasons.append("Abused free web host or dynamic DNS")

    if any(b in url_lower for b in [
        "outlook", "microsof", "coinbase", "sbcglobal", "bancogeneral", "ficohs",
        "yah100", "codashop", "micloud", "agreementmail", "findyourjacket", "mediafirew"
    ]):
        is_malicious = True
        reasons.append("Brand impersonation / typosquatting")
        
    if "0000" in url_lower or "0.0.0.0" in url_lower:
        is_malicious = True
        reasons.append("Extreme repetitive zeroes / obfuscation")

    # False negative: Malicious URL classified as Safe (0-19) or Low Risk (20-39)
    if is_malicious and res.threat_score < 40:
        fn_list.append({
            "index": i,
            "url": raw_url,
            "vigilo_score": res.threat_score,
            "vigilo_status": res.status,
            "category": res.category,
            "reasons": reasons
        })

print(f"Total False Negatives Found: {len(fn_list)}")
print(json.dumps(fn_list, indent=2))
