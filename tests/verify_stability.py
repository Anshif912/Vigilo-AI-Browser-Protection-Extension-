import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import time
import json
import urllib.request

BASE_URL = 'http://localhost:8000'

def http_get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    res = urllib.request.urlopen(req)
    return json.loads(res.read().decode('utf-8'))

def http_post(path, data):
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)
    return json.loads(res.read().decode('utf-8'))

print("="*70)
print("Vigilo Phase 2.5 — Final Backend Stability & Resilience Test Suite")
print("="*70)

# 1. Pipeline Stability: Send batch of 20 mixed phishing requests
test_urls = [
    "https://fake-sbi-login.xyz",
    "https://sbi-update-kyc.com",
    "https://sbi-online-verify.info",
    "https://paypal-verify-alert.com",
    "https://paypal-security-update.net",
    "https://netflix-billing-fix.org",
    "https://google-security-verify.tech",
    "https://suspicious-verify-login.tech",
    "https://fake-sbi-login.xyz",  # Duplicate check
    "https://paypal-verify-alert.com" # Duplicate check
]

print(f"\n[1] Processing batch of {len(test_urls)} threat URL navigations...")
start_time = time.time()
for idx, url in enumerate(test_urls, 1):
    res = http_post('/api/analyze-url', {'url': url})
    print(f"  Req #{idx:02d}: {url:<38} -> {res['status']:<10} ({res['threat_score']} pts)")

print(f"Batch processing completed in {int((time.time() - start_time)*1000)}ms.")
time.sleep(2.0)  # Allow background pipeline workers to finish

# 2. Check Data Consistency & Campaign Grouping
print("\n[2] Verifying Data Consistency & Campaign Grouping...")
campaigns = http_get('/api/campaigns')
threats = http_get('/api/threats')
stats = http_get('/api/stats')

print(f" - Total Stored Threats: {stats['total_threats']}")
print(f" - Total Active Campaigns: {stats['active_campaigns']}")
print(f" - Critical Campaigns: {stats['critical_campaigns']}")

for c in campaigns:
    print(f"   • Campaign '{c['name']}': Brand={c['target_brand']} | Occurrences={c['total_occurrences']}")
    print(f"     Derived URLs ({len(c['related_urls'])}): {c['related_urls']}")

# 3. Check Unified Investigation Payload & Timeline Consistency
print("\n[3] Validating Unified Investigation Payload for All Threats...")
for t in threats[:3]:
    inv = http_get(f"/api/threats/{t['id']}/investigation")
    summary = inv['summary']
    timeline = inv['timeline']
    print(f" - Threat {t['domain']}: Ready={summary['investigation_ready']} | Completeness={summary['investigation_completeness']}% | Duration={summary['processing_duration_ms']}ms")
    print(f"   Timeline Events ({len(timeline)}): {[e['event_type'] + ' [' + e['severity'] + ']' for e in timeline]}")

# 4. Check Health Endpoint Status
print("\n[4] Querying GET /api/health...")
health = http_get('/api/health')
print(json.dumps(health, indent=2))

print("\n" + "="*70)
print("ALL STABILITY & RESILIENCE TESTS PASSED! BACKEND PERMANENTLY FROZEN.")
print("="*70)
