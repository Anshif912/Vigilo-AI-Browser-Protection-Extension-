import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from engine.fusion_engine import ThreatFusionEngine

def run_fusion_tests():
    print("=" * 70)
    print("VIGILO v4.1 — RULE FUSION & DECISION GATING VERIFICATION")
    print("=" * 70)

    engine = ThreatFusionEngine()
    passed = 0
    total = 0

    scenarios = [
        {
            "name": "Unknown legitimate domain (unseen, clean structure)",
            "url": "https://unseen-developer-portfolio.example",
            "expected_status": ["Safe", "Low Risk", "UNVERIFIED"],
            "max_score": 35
        },
        {
            "name": "Typosquatting brand impersonation",
            "url": "https://g00gle-security-update.xyz",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 40
        },
        {
            "name": "Subdomain brand impersonation",
            "url": "https://google.com.example.org",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 30
        },
        {
            "name": "Path brand impersonation",
            "url": "https://evil.xyz/paypal/login",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 40
        },
        {
            "name": "Typosquat brand registration",
            "url": "https://paypal-login-secure.xyz",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 40
        },
        {
            "name": "Brandless generic phishing portal",
            "url": "https://secure-document-share-login.xyz",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 40
        },
        {
            "name": "Critical banking phishing target",
            "url": "https://sbi-kyc-update-portal.online",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 40
        },
        {
            "name": "Crypto wallet harvesting scam",
            "url": "https://binance-wallet-recovery.xyz",
            "expected_status": ["Suspicious", "High Risk", "Critical"],
            "min_score": 40
        }
    ]

    for sc in scenarios:
        total += 1
        res = engine.analyze(sc["url"])
        print(f"\nScenario: {sc['name']}")
        print(f"  URL: {sc['url']}")
        print(f"  Status: {res.status} | Score: {res.threat_score}/100 | Confidence: {res.confidence}%")
        
        status_pass = res.status in sc["expected_status"]
        score_pass = True
        if "max_score" in sc:
            score_pass = res.threat_score <= sc["max_score"]
        if "min_score" in sc:
            score_pass = res.threat_score >= sc["min_score"]

        if status_pass and score_pass:
            print("  [PASS] Rule fusion gate resolved correctly.")
            passed += 1
        else:
            print(f"  [FAIL] Failed constraints. Expected status in {sc['expected_status']}")

    print("\n" + "=" * 70)
    print(f"RULE FUSION VERIFICATION RESULTS: {passed}/{total} PASSED ({round(passed/total*100, 1)}%)")
    print("=" * 70)

    if passed < total:
        sys.exit(1)

if __name__ == "__main__":
    run_fusion_tests()
