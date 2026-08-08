import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import time
from services.url_analyzer import UniversalURLAnalyzer

print("=" * 90)
print("VIGILO v3.0 — ENTERPRISE THREAT DETECTION RULE ENGINE VALIDATION SUITE")
print("=" * 90)

test_cases = [
    {"name": "Legitimate Domain (Google)", "url": "https://google.com", "expected_status": "Safe"},
    {"name": "Legitimate Domain (Hugging Face)", "url": "https://huggingface.co", "expected_status": "Safe"},
    {"name": "Unknown Clean Domain", "url": "https://myportfolio.dev", "expected_status": "Safe"},
    {"name": "Subdomain Brand Impersonation", "url": "https://google.com.example.org", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Typosquatting / Homograph", "url": "https://g00gle-security-update.xyz", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Brandless Phishing", "url": "https://secure-document-share-login.xyz", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Path Brand Impersonation", "url": "https://mail.printakid.com/www.online.americanexpress.com/index.html", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Query Brand Abuse", "url": "https://evil.net/page.html?redirect=paypal.com", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Credential Harvesting", "url": "https://secure-document-share-login.xyz", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Banking Phishing", "url": "https://sbi-kyc-update-portal.online", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Crypto Phishing", "url": "https://binance-wallet-recovery.xyz", "expected_status": ["Suspicious", "High Risk", "Critical"]},
    {"name": "Government Impersonation", "url": "https://irs-tax-refund-verify.online", "expected_status": ["Suspicious", "High Risk", "Critical"]}
]

passed_count = 0

for idx, tc in enumerate(test_cases, 1):
    print(f"\n[{idx}] Test Case: {tc['name']}")
    print(f"    URL: {tc['url']}")
    
    t0 = time.time()
    res = UniversalURLAnalyzer.analyze_url(tc['url'])
    duration_ms = round((time.time() - t0) * 1000, 2)
    
    print(f"    Verdict: {res.status} | Threat Score: {res.threat_score}/100 | Confidence: {res.confidence}% ({res.confidence_level})")
    print(f"    Category: {res.category} | Sub Category: {res.sub_category}")
    print(f"    Identity: {res.website_identity} | Registered Domain: {res.ioc['registered_domain']}")
    print(f"    Rules Evaluated: {res.structured_evidence['total_rules_evaluated']} | Rules Matched: {len(res.structured_evidence['matched_rules'])}")
    print(f"    Processing Time: {duration_ms} ms")
    
    print("    Matched Rules:")
    for m in res.structured_evidence['matched_rules']:
        print(f"      • [{m['rule_id']}] {m['rule_name']} (+{m['weight']} pts) -> {m['evidence']}")

    expected = tc['expected_status']
    if isinstance(expected, list):
        is_pass = res.status in expected
    else:
        is_pass = res.status == expected

    if is_pass:
        passed_count += 1
        print(f"    [PASS] Verified successfully")
    else:
        print(f"    [FAIL] Expected {expected}, got {res.status}")

print("\n" + "=" * 90)
print(f"VALIDATION SUMMARY: {passed_count}/{len(test_cases)} SCENARIOS PASSED ({round(passed_count / len(test_cases) * 100, 1)}%)")
print("=" * 90)
