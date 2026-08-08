import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
from services.url_analyzer import UniversalURLAnalyzer

print("=" * 85)
print("VIGILO v2.6 — PATH & SUBPATH BRAND IMPERSONATION TEST SUITE")
print("=" * 85)

test_urls = [
    "https://mail.printakid.com/www.online.americanexpress.com/index.html",
    "https://example.org/google.com/login",
    "https://abc.xyz/paypal.com/verify",
    "https://evil.net/login.microsoft.com/auth"
]

for idx, url in enumerate(test_urls, 1):
    print(f"\n[{idx}] Testing URL: {url}")
    res = UniversalURLAnalyzer.analyze_url(url)
    
    print(f"    Status: {res.status} | Threat Score: {res.threat_score}/100 | Confidence: {res.confidence}% ({res.confidence_level})")
    print(f"    Category: {res.category} | Sub Category: {res.sub_category}")
    print(f"    Target Brand: {res.website_identity} | Registered Domain: {res.ioc['registered_domain']}")
    print(f"    Reasoning Summary: {res.risk_reasoning_summary}")
    print("    Score Breakdown:")
    for b in res.score_breakdown:
        print(f"      • [{b['factor']}] +{b['weight']} pts -> {b['evidence']}")
    print("    Analysis Trace:")
    for tr in res.analysis_trace:
        print(f"      [{tr['stage']}] -> {tr['status']} ({tr.get('result', '')})")

    # Verification assertions
    assert res.sub_category == "Path Brand Impersonation", f"Expected sub_category 'Path Brand Impersonation', got '{res.sub_category}'"
    assert any(b['factor'] == "Path Brand Impersonation" for b in res.score_breakdown), "Expected factor 'Path Brand Impersonation' in score breakdown"
    assert res.status in ["Suspicious", "High Risk", "Critical"], f"Expected Suspicious/High Risk/Critical, got {res.status}"
    
    print(f"    [PASS] Test Case {idx} Verified 100%!")

print("\n" + "=" * 85)
print("VIGILO v2.6 PATH BRAND IMPERSONATION VERIFICATION COMPLETE — 100% PASSED!")
print("=" * 85)
