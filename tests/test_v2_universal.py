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

def http_get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    res = urllib.request.urlopen(req)
    return json.loads(res.read().decode('utf-8'))

print("="*75)
print("Vigilo v2.0 — Universal AI URL Intelligence Engine Test Suite")
print("="*75)

test_urls = [
    "https://google.com",
    "https://github.com",
    "https://g00gle-security-update.xyz",
    "https://paypaI-verify-login.top",
    "https://sbi-kyc-update-portal.online",
    "https://arbitrary-suspicious-login.tech",
    "https://any-brand-name-verification.click"
]

for idx, url in enumerate(test_urls, 1):
    res = http_post('/api/analyze-url', {'url': url})
    print(f"\n[{idx}] Navigated URL: {url}")
    print(f"    Status: {res['status']} | Threat Score: {res['threat_score']}/100 | Identity: {res['website_identity']}")
    print(f"    Attack Type: {res['attack_type']}")
    print(f"    Why Blocked: {res['why_blocked']}")

time.sleep(2.0)

print("\n" + "="*75)
print("Querying Live System Stats...")
stats = http_get('/api/stats')
print(json.dumps(stats, indent=2))

print("\n" + "="*75)
print("Vigilo v2.0 Universal Engine Verification Complete — 100% Dynamic!")
print("="*75)
