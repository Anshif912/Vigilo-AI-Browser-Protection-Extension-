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
print("Vigilo Phase 2.5 — Threat Intelligence Enhancement Test Suite")
print("="*65)

# 1. Test Health Endpoint
print("\n[1] Querying GET /api/health...")
health = http_get('/api/health')
print(json.dumps(health, indent=2))

# 2. Trigger Phishing Detection 1: fake-sbi-login.xyz
print("\n[2] Triggering POST /api/analyze-url for 'https://fake-sbi-login.xyz'...")
res1 = http_post('/api/analyze-url', {'url': 'https://fake-sbi-login.xyz'})
print(f"Protection Response: {res1['status']} | Score: {res1['threat_score']} | Identity: {res1['website_identity']}")

time.sleep(1.5)

# 3. Query Stored Threats
threats = http_get('/api/threats')
if not threats:
    print("ERROR: No threat record found!")
    exit(1)

threat_id = threats[0]['id']
campaign_id = threats[0]['campaign_id']

# 4. Query Score Breakdown GET /api/threats/{id}/score
print(f"\n[3] Querying GET /api/threats/{threat_id}/score...")
score_res = http_get(f"/api/threats/{threat_id}/score")
print(json.dumps(score_res, indent=2))

# 5. Query IOC GET /api/threats/{id}/ioc
print(f"\n[4] Querying GET /api/threats/{threat_id}/ioc...")
ioc_res = http_get(f"/api/threats/{threat_id}/ioc")
print(json.dumps(ioc_res, indent=2))

# 6. Query Tags GET /api/threats/{id}/tags
print(f"\n[5] Querying GET /api/threats/{threat_id}/tags...")
tags_res = http_get(f"/api/threats/{threat_id}/tags")
print(json.dumps(tags_res, indent=2))

# 7. Query Campaign Timeline GET /api/campaigns/{id}/timeline
print(f"\n[6] Querying GET /api/campaigns/{campaign_id}/timeline...")
timeline_res = http_get(f"/api/campaigns/{campaign_id}/timeline")
print(json.dumps(timeline_res, indent=2))

# 8. Query Unified Investigation GET /api/threats/{id}/investigation
print(f"\n[7] Querying Unified Investigation GET /api/threats/{threat_id}/investigation...")
investigation_res = http_get(f"/api/threats/{threat_id}/investigation")
print(json.dumps(investigation_res, indent=2))

print("\n" + "="*65)
print("Vigilo Phase 2.5 Verification Complete — All Enhancements Active!")
print("="*65)
