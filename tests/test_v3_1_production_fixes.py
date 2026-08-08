import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
import time
from services.url_analyzer import UniversalURLAnalyzer

print("=" * 90)
print("VIGILO v3.1 — PRODUCTION FIXES & CONNECTION SECURITY VALIDATION SUITE")
print("=" * 90)

scenarios = [
    {
        "name": "1. Insecure HTTP Unknown Domain (HTTP myportfolio.dev)",
        "url": "http://myportfolio.dev",
        "expected_threat": "Safe",
        "expected_conn": "Not Secure",
        "expected_overall": "Low Risk"
    },
    {
        "name": "2. Secure Official Platform (HTTPS google.com)",
        "url": "https://google.com",
        "expected_threat": "Safe",
        "expected_conn": "Secure",
        "expected_overall": "Safe"
    },
    {
        "name": "3. HTTP Path Impersonation (Smiles on coincoele.com.br)",
        "url": "http://www.coincoele.com.br/Scripts/smiles/?pt-br/Paginas/default.aspx",
        "expected_threat": "Suspicious",
        "expected_conn": "Not Secure",
        "expected_overall": "Suspicious"
    },
    {
        "name": "4. Typosquatting Phishing (g00gle-security-update.xyz)",
        "url": "https://g00gle-security-update.xyz",
        "expected_threat": "Suspicious",
        "expected_conn": "Secure",
        "expected_overall": "Suspicious"
    },
    {
        "name": "5. Critical Financial Phishing (sbi-kyc-update-portal.online)",
        "url": "https://sbi-kyc-update-portal.online",
        "expected_threat": "Critical",
        "expected_conn": "Secure",
        "expected_overall": "Critical"
    }
]

passed_count = 0

for idx, sc in enumerate(scenarios, 1):
    print(f"\n[{idx}] {sc['name']}")
    print(f"    URL: {sc['url']}")
    
    t0 = time.time()
    res = UniversalURLAnalyzer.analyze_url(sc['url'])
    duration_ms = round((time.time() - t0) * 1000, 2)
    
    print(f"    Threat Status: {res.status} | Connection Security: {res.connection_security} ({res.transport_protocol})")
    print(f"    Overall Status: {res.overall_status} | Threat Score: {res.threat_score}/100 | Confidence: {res.confidence}% ({res.confidence_level})")
    print(f"    Category: {res.category} | Sub Category: {res.sub_category}")
    print(f"    Security Reason: {res.security_reason}")
    print(f"    Execution Time: {duration_ms} ms (Target <300ms)")

    assert res.status == sc['expected_threat'], f"Expected threat {sc['expected_threat']}, got {res.status}"
    assert res.connection_security == sc['expected_conn'], f"Expected connection {sc['expected_conn']}, got {res.connection_security}"
    assert res.overall_status == sc['expected_overall'], f"Expected overall {sc['expected_overall']}, got {res.overall_status}"
    assert duration_ms < 300, f"Execution time {duration_ms}ms exceeded 300ms limit"

    passed_count += 1
    print("    [PASS] 100% Correct Classification & Response Time!")

print("\n" + "=" * 90)
print(f"VIGILO v3.1 PRODUCTION VALIDATION COMPLETE: {passed_count}/{len(scenarios)} PASSED (100.0%)")
print("=" * 90)
