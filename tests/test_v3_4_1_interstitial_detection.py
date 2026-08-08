import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
from services.url_analyzer import UniversalURLAnalyzer

print("=" * 95)
print("VIGILO v3.4.1 — BROWSER SECURITY INTERSTITIAL & VENDOR WARNING DETECTION QA SUITE")
print("=" * 95)

interstitial_scenarios = [
    {
        "name": "1. Cloudflare Suspected Phishing Warning Page",
        "url": "https://phishing-target.com",
        "dom_title": "Attention Required! | Cloudflare",
        "dom_text": "Suspected Phishing Page. This website has been reported as a phishing site to Cloudflare.",
        "expected_status": "Critical",
        "expected_score": 100,
        "expected_category": "Browser Security Warning"
    },
    {
        "name": "2. Google Safe Browsing Deceptive Site Interstitial",
        "url": "https://malicious-portal.net",
        "dom_title": "Deceptive site ahead",
        "dom_text": "Attackers on malicious-portal.net may trick you into doing something dangerous like installing software or revealing personal information.",
        "expected_status": "Critical",
        "expected_score": 100,
        "expected_category": "Browser Security Warning"
    },
    {
        "name": "3. Microsoft Defender SmartScreen Warning",
        "url": "https://fake-login-bank.org",
        "dom_title": "Microsoft Defender SmartScreen",
        "dom_text": "This site has been reported as unsafe. Microsoft recommends you do not continue to this site.",
        "expected_status": "Critical",
        "expected_score": 100,
        "expected_category": "Browser Security Warning"
    },
    {
        "name": "4. Firefox Deceptive Site Ahead Warning",
        "url": "https://bad-phishing-host.xyz",
        "dom_title": "Deceptive Site Ahead",
        "dom_text": "Firefox blocked this page because it might try to trick you into installing software or disclosing personal information.",
        "expected_status": "Critical",
        "expected_score": 100,
        "expected_category": "Browser Security Warning"
    }
]

passed_count = 0

for idx, scenario in enumerate(interstitial_scenarios, 1):
    print(f"\n[{idx}] {scenario['name']}")
    print(f"    URL: {scenario['url']}")
    print(f"    DOM Title: '{scenario['dom_title']}'")
    
    res = UniversalURLAnalyzer.analyze_url(
        url=scenario['url'],
        dom_title=scenario['dom_title'],
        dom_text=scenario['dom_text']
    )
    
    print(f"    Threat Verdict: {res.status} | Threat Score: {res.threat_score}/100")
    print(f"    Category: {res.category} | Sub-Category: {res.sub_category}")
    print(f"    Reasoning Summary: {res.risk_reasoning_summary}")

    assert res.status == scenario['expected_status'], f"Expected {scenario['expected_status']}, got {res.status}"
    assert res.threat_score == scenario['expected_score'], f"Expected {scenario['expected_score']}, got {res.threat_score}"
    assert res.category == scenario['expected_category'], f"Expected {scenario['expected_category']}, got {res.category}"

    passed_count += 1
    print("    [PASS] 100% Interstitial Override & Single Source Telemetry Verified!")

print("\n" + "=" * 95)
print(f"VIGILO v3.4.1 INTERSTITIAL QA VERIFICATION COMPLETE: {passed_count}/{len(interstitial_scenarios)} PASSED (100.0%)")
print("=" * 95)
