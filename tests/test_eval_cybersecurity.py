import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
from services.url_analyzer import UniversalURLAnalyzer


print("=" * 80)
print("VIGILO v2.5 ENTERPRISE URL INTELLIGENCE ENGINE — EVALUATION TEST SUITE")
print("=" * 80)

test_scenarios = [
    {
        "name": "1. Unknown Benign Domain (Dev Portfolio)",
        "url": "https://myportfolio.dev"
    },
    {
        "name": "2. Unknown Legitimate Platform (Hugging Face)",
        "url": "https://huggingface.co"
    },
    {
        "name": "3. Brandless Phishing Domain (Credential Harvesting)",
        "url": "https://secure-document-share-login.xyz"
    },
    {
        "name": "4. Subdomain Brand Impersonation (Google on Example.org)",
        "url": "https://google.com.example.org"
    },
    {
        "name": "5. Typosquatting & Homograph (Fake SBI Login)",
        "url": "https://g00gle-security-update.xyz"
    },
    {
        "name": "6. Financial Phishing (SBI KYC Update)",
        "url": "https://sbi-kyc-update-portal.online"
    }
]

passed_count = 0

for idx, item in enumerate(test_scenarios, 1):
    print(f"\n--- Scenario [{idx}]: {item['name']} ---")
    print(f"URL: {item['url']}")
    
    res = UniversalURLAnalyzer.analyze_url(item['url'])
    
    print(f"Status: {res.status} | Threat Score: {res.threat_score}/100 | Confidence: {res.confidence}% ({res.confidence_level})")
    print(f"Category: {res.category} | Sub-Category: {res.sub_category}")
    print(f"Website Identity: {res.website_identity} | Attack Type: {res.attack_type}")
    print(f"Registered Domain: {res.ioc['registered_domain']} | TLD: {res.ioc['tld']}")
    print(f"Fingerprint: {res.threat_fingerprint[:16]}... | Performance Total: {res.performance['total_ms']}ms")
    print(f"Risk Narrative: {res.risk_reasoning_summary}")
    print("\nItemized Weighted Score Breakdown:")
    for b in res.score_breakdown:
        print(f"  • [{b['factor']}] +{b['weight']} pts -> {b['evidence']}")
        
    print("\nDetection Trace:")
    for t in res.analysis_trace:
        print(f"  [{t['stage']}] -> {t['status']} ({t.get('result', '')})")

    # Verification assertions
    if item["name"].startswith("1."):
        assert res.status in ["Safe", "Low Risk"], f"Expected Safe/Low Risk, got {res.status}"
        assert res.threat_score <= 20, f"Expected low threat score, got {res.threat_score}"
        print("  [PASS] Correctly classified as Safe/Low Risk benign unknown domain")
        
    elif item["name"].startswith("2."):
        assert res.status in ["Safe", "Low Risk"], f"Expected Safe/Low Risk, got {res.status}"
        assert res.threat_score <= 15, f"Expected low threat score, got {res.threat_score}"
        print("  [PASS] Correctly classified as Safe legitimate platform")
        
    elif item["name"].startswith("3."):
        assert res.status in ["Suspicious", "High Risk", "Critical"], f"Expected Suspicious/High Risk/Critical, got {res.status}"
        assert res.threat_score >= 50, f"Expected high threat score for brandless phishing, got {res.threat_score}"
        assert "login" in res.ioc["keywords"] or "secure" in res.ioc["keywords"], "Expected matched credential keywords"
        print("  [PASS] Successfully detected brandless phishing via keywords + TLD + entropy")

    elif item["name"].startswith("4."):
        assert res.ioc["registered_domain"] == "example.org", f"Expected PSL registered_domain example.org, got {res.ioc['registered_domain']}"
        assert res.website_identity.lower() == "google", f"Expected Google identity, got {res.website_identity}"
        assert res.status in ["High Risk", "Critical"], f"Expected High Risk/Critical, got {res.status}"
        print("  [PASS] Public Suffix List correctly parsed example.org and detected Google subdomain impersonation")

    elif item["name"].startswith("5."):
        assert res.status in ["Suspicious", "High Risk", "Critical"], f"Expected Suspicious/High Risk/Critical, got {res.status}"
        print("  [PASS] Successfully detected visual homograph / typosquatting")

    elif item["name"].startswith("6."):
        assert res.status in ["Suspicious", "High Risk", "Critical"], f"Expected Suspicious/High Risk/Critical, got {res.status}"
        print("  [PASS] Successfully detected financial phishing portal")

    passed_count += 1

print("\n" + "=" * 80)
print(f"VERIFICATION COMPLETE: {passed_count}/{len(test_scenarios)} SCENARIOS PASSED 100% PERFECTLY!")
print("=" * 80)
