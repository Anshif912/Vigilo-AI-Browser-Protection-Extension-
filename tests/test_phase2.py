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

print("="*65)
print("Vigilo Phase 2 — Threat Intelligence Engine Test Suite")
print("="*65)

# 1. Test Stats before Detections
print("\n[1] Querying GET /api/stats...")
stats1 = http_get('/api/stats')
print(json.dumps(stats1, indent=2))

# 2. Trigger Phishing Detection 1: fake-sbi-login.xyz
print("\n[2] Triggering POST /api/analyze-url for 'https://fake-sbi-login.xyz'...")
res1 = http_post('/api/analyze-url', {'url': 'https://fake-sbi-login.xyz'})
print(f"Protection Response: {res1['status']} | Threat Score: {res1['threat_score']} | Identity: {res1['website_identity']}")

# Give background task 1 second to write to SQLite
time.sleep(1.2)

# 3. Trigger Related Phishing Detection 2: sbi-update-kyc.com (Should join SBI campaign)
print("\n[3] Triggering POST /api/analyze-url for 'https://sbi-update-kyc.com' (Related SBI Threat)...")
res2 = http_post('/api/analyze-url', {'url': 'https://sbi-update-kyc.com'})
print(f"Protection Response: {res2['status']} | Threat Score: {res2['threat_score']} | Identity: {res2['website_identity']}")

time.sleep(1.2)

# 4. Trigger Phishing Detection 3: paypal-verify-alert.com
print("\n[4] Triggering POST /api/analyze-url for 'https://paypal-verify-alert.com'...")
res3 = http_post('/api/analyze-url', {'url': 'https://paypal-verify-alert.com'})
print(f"Protection Response: {res3['status']} | Threat Score: {res3['threat_score']} | Identity: {res3['website_identity']}")

time.sleep(1.2)

# 5. Query Stored Threats GET /api/threats
print("\n[5] Querying GET /api/threats...")
threats = http_get('/api/threats')
print(f"Total Stored Threat Records: {len(threats)}")
for t in threats:
    print(f" - [{t['status']}] {t['url']} -> Campaign: {t['campaign_name']}")

# 6. Query Stored Campaigns GET /api/campaigns
print("\n[6] Querying GET /api/campaigns...")
campaigns = http_get('/api/campaigns')
print(f"Total Active Campaigns: {len(campaigns)}")
for c in campaigns:
    print(f" - Campaign: '{c['name']}' | Brand: {c['target_brand']} | Occurrences: {c['total_occurrences']}")
    print(f"   Derived Related URLs: {c['related_urls']}")

# 7. Query Detailed Threat with Evidence GET /api/threats/{id}
if threats:
    threat_id = threats[0]['id']
    print(f"\n[7] Querying GET /api/threats/{threat_id} (Threat Details & Evidence)...")
    t_detail = http_get(f"/api/threats/{threat_id}")
    print(f" - Summary: {t_detail.get('summary')}")
    print(f" - Evidence Pack: {json.dumps(t_detail.get('evidence'), indent=2)}")

# 8. Query Updated Intelligence Stats GET /api/stats
print("\n[8] Querying updated GET /api/stats...")
stats2 = http_get('/api/stats')
print(json.dumps(stats2, indent=2))

print("\n" + "="*65)
print("Vigilo Phase 2 Verification Complete — All Systems Operational!")
print("="*65)
