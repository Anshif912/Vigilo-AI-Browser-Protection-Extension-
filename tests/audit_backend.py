import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
import urllib.request

BASE_URL = 'http://localhost:8000'

def test_endpoint(name, path, method="GET", body=None):
    try:
        url = f"{BASE_URL}{path}"
        headers = {'Content-Type': 'application/json'} if body else {}
        data = json.dumps(body).encode('utf-8') if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        res = urllib.request.urlopen(req)
        code = res.getcode()
        content = json.loads(res.read().decode('utf-8'))
        print(f"[{name}] {method} {path} -> HTTP {code} PASS")
        return content
    except Exception as e:
        print(f"[{name}] {method} {path} -> FAIL: {e}")
        return None

print("==================================================")
print("VIGILO BACKEND REST API ACCEPTANCE VERIFICATION")
print("==================================================")

# 1. Health Endpoint
health = test_endpoint("Health Status", "/api/health")

# 2. Analyze URL Endpoint
analyze_res = test_endpoint("URL Analysis", "/api/analyze-url", method="POST", body={"url": "https://fake-sbi-login.xyz"})

# 3. Stats Endpoint
stats = test_endpoint("System Stats", "/api/stats")

# 4. Campaigns Endpoint
campaigns = test_endpoint("Campaigns List", "/api/campaigns")

# 5. Threats Endpoint
threats = test_endpoint("Threats List", "/api/threats")

# 6. Unified Investigation Endpoint
if threats and len(threats) > 0:
    threat_id = threats[0]['id']
    investigation = test_endpoint("Unified Investigation", f"/api/threats/{threat_id}/investigation")

print("==================================================")
