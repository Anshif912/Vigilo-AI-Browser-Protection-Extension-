import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import time
import json
from services.url_analyzer import UniversalURLAnalyzer

print("=" * 95)
print("VIGILO v3.3 — PRODUCTION COMPLETION & HACKATHON READINESS END-TO-END QA SUITE")
print("=" * 95)

test_urls = [
    {
        "name": "1. Official Domain (Safe)",
        "url": "https://google.com",
        "expected_status": "Safe",
        "expected_conn": "Secure",
        "expected_overall": "Safe"
    },
    {
        "name": "2. Insecure Unknown Domain (HTTP myportfolio.dev)",
        "url": "http://myportfolio.dev",
        "expected_status": "Safe",
        "expected_conn": "Not Secure",
        "expected_overall": "Low Risk"
    },
    {
        "name": "3. Typosquatting Phishing (g00gle-security-update.xyz)",
        "url": "https://g00gle-security-update.xyz",
        "expected_status": "Suspicious",
        "expected_conn": "Secure",
        "expected_overall": "Suspicious"
    },
    {
        "name": "4. Banking Fraud (sbi-kyc-update-portal.online)",
        "url": "https://sbi-kyc-update-portal.online",
        "expected_status": "Critical",
        "expected_conn": "Secure",
        "expected_overall": "Critical"
    },
    {
        "name": "5. Path Impersonation (coincoele.com.br/Scripts/smiles/...)",
        "url": "http://www.coincoele.com.br/Scripts/smiles/?pt-br/Paginas/default.aspx",
        "expected_status": "Suspicious",
        "expected_conn": "Not Secure",
        "expected_overall": "Suspicious"
    },
    {
        "name": "6. Subdomain Impersonation (google.com.example.org)",
        "url": "https://google.com.example.org",
        "expected_status": "High Risk",
        "expected_conn": "Secure",
        "expected_overall": "High Risk"
    },
    {
        "name": "7. Brandless Credential Harvesting (secure-document-share-login.xyz)",
        "url": "https://secure-document-share-login.xyz",
        "expected_status": "High Risk",
        "expected_conn": "Secure",
        "expected_overall": "High Risk"
    }
]

passed_count = 0
results = []

for idx, item in enumerate(test_urls, 1):
    print(f"\n[{idx}] {item['name']}")
    print(f"    URL: {item['url']}")
    
    t0 = time.time()
    res = UniversalURLAnalyzer.analyze_url(item['url'])
    duration_ms = round((time.time() - t0) * 1000, 2)
    
    threat_status = res.status
    conn_sec = res.connection_security
    overall = res.overall_status
    score = res.threat_score
    confidence = res.confidence
    ai_exp = res.ai_explanation or {}
    
    print(f"    Threat Status: {threat_status} | Connection: {conn_sec} ({res.transport_protocol}) | Overall: {overall}")
    print(f"    Score: {score}/100 | Confidence: {confidence}% ({res.confidence_level}) | Threat Type: {ai_exp.get('threat_type', 'N/A')}")
    print(f"    Execution Time: {duration_ms} ms (Target <300ms)")

    assert threat_status == item['expected_status'], f"Expected threat {item['expected_status']}, got {threat_status}"
    assert conn_sec == item['expected_conn'], f"Expected connection {item['expected_conn']}, got {conn_sec}"
    assert overall == item['expected_overall'], f"Expected overall {item['expected_overall']}, got {overall}"
    assert duration_ms < 300, f"Execution time {duration_ms}ms exceeded 300ms target"

    passed_count += 1
    results.append({
        "url": item['url'],
        "threat_status": threat_status,
        "connection_security": conn_sec,
        "overall_status": overall,
        "threat_score": score,
        "duration_ms": duration_ms,
        "status": "PASS"
    })
    print("    [PASS] 100% Correct Classification & Single Source Telemetry!")

print("\n" + "=" * 95)
print(f"VIGILO v3.3 FINAL QA VERIFICATION COMPLETE: {passed_count}/{len(test_urls)} PASSED (100.0%)")
print("=" * 95)
