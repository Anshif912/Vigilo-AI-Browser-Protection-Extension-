import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from engine.fusion_engine import ThreatFusionEngine

def run_fp_tests():
    print("=" * 70)
    print("VIGILO v4.1 — FALSE POSITIVE REGRESSION SUITE")
    print("=" * 70)

    engine = ThreatFusionEngine()
    passed = 0
    total = 0

    test_cases = [
        # Domain, Expected Status
        ("https://ollama.com", "Safe"),
        ("https://google.com", "Safe"),
        ("https://github.com", "Safe"),
        ("https://microsoft.com", "Safe"),
        ("https://paypal.com", "Safe"),
        ("https://login.microsoftonline.com", "Safe"),
        ("https://github.com/login", "Safe"),
        ("https://apple.com", "Safe"),
        ("https://amazon.com", "Safe"),
        ("https://cloudflare.com", "Safe"),
        ("https://vercel.com", "Safe"),
        ("https://huggingface.co", "Safe"),
        ("https://passportindia.gov.in", "Safe"),
    ]

    for url, expected in test_cases:
        total += 1
        res = engine.analyze(url)
        print(f"  URL: {url:<35} | Status: {res.status:<15} | Score: {res.threat_score:<3}")
        
        if res.status == expected and res.threat_score <= 19:
            print(f"    [PASS] Clean domain verified correctly.")
            passed += 1
        else:
            print(f"    [FAIL] Expected {expected}, got {res.status} (Score: {res.threat_score})")

    print("\n" + "=" * 70)
    print(f"FALSE POSITIVE REGRESSION RESULTS: {passed}/{total} PASSED ({round(passed/total*100, 1)}%)")
    print("=" * 70)

    if passed < total:
        sys.exit(1)

if __name__ == "__main__":
    run_fp_tests()
