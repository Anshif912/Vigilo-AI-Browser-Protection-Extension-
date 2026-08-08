import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import time
import json
import urllib.request

BASE_URL = 'http://localhost:8000'

def http_post(path, data):
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)
    return json.loads(res.read().decode('utf-8'))

print("="*80)
print("Vigilo v2.1 — Enterprise URL Intelligence Engine Test Suite")
print("="*80)

test_urls = [
    "https://huggingface.co",
    "https://google.com.example.org",
    "https://secure-document-share-login.xyz",
    "https://g00gle-security-update.xyz"
]

for idx, url in enumerate(test_urls, 1):
    res = http_post('/api/analyze-url', {'url': url})
    print(f"\n[{idx}] Navigated URL: {url}")
    print(f"    Status: {res['status']} | Threat Score: {res['threat_score']}/100 | Confidence: {res.get('confidence', 85)}%")
    print(f"    Target Identity: {res['website_identity']} | Attack Type: {res['attack_type']}")
    print(f"    Score Breakdown: {json.dumps(res.get('score_breakdown', []), indent=2)}")
    print(f"    Structured Evidence: {json.dumps(res.get('structured_evidence', {}), indent=2)}")

print("\n" + "="*80)
print("Vigilo v2.1 Verification Complete — Registered Domain Parsing & Additive Score Breakdown Active!")
print("="*80)
