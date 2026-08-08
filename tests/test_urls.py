import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
import urllib.request

urls = [
    'https://google.com',
    'https://github.com',
    'https://fake-sbi-login.xyz',
    'https://suspicious-verify-login.tech'
]

print("="*65)
print("Vigilo Phase 1 — Final 4-URL Test Suite Verification")
print("="*65)

for url in urls:
    req = urllib.request.Request(
        'http://localhost:8000/api/analyze-url',
        data=json.dumps({'url': url}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode('utf-8'))
    print(f"URL: {url:<38} -> Status: {data['status']:<10} | Score: {data['threat_score']:<3} | Identity: {data['website_identity']}")

print("="*65)
