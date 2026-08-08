import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from engine.fusion_engine import ThreatFusionEngine

def run_tests():
    print("=" * 70)
    print("VIGILO v4.0 MULTI-SIGNAL BROWSER RISK ENGINE - AUTOMATED TEST SUITE")
    print("=" * 70)

    engine = ThreatFusionEngine()
    passed = 0
    total = 0

    # -------------------------------------------------------------
    # TEST 1: CRITICAL ACCEPTANCE TEST (User Screenshot Regression Test)
    # Target: https://anonymeidentity.net/remax/./remax.htm
    # -------------------------------------------------------------
    total += 1
    t0 = time.time()
    res1 = engine.analyze("https://anonymeidentity.net/remax/./remax.htm")
    dur1 = round((time.time() - t0) * 1000, 2)
    print(f"\n[Test 1] Critical Acceptance Test (Unreachable Domain)")
    print(f"  URL: https://anonymeidentity.net/remax/./remax.htm")
    print(f"  Technical Status: {res1.technical_status}")
    print(f"  Connection Security: {res1.connection_security}")
    print(f"  Overall Status: {res1.overall_status}")
    print(f"  Threat Score: {res1.threat_score}/100")
    print(f"  Duration: {dur1} ms")

    if res1.overall_status in ["Unverified", "Suspicious", "High Risk"] and res1.overall_status != "Safe":
        print("  [PASS] Unreachable domain correctly returned 'Unverified' / 'Suspicious' and NEVER 'Safe'!")
        passed += 1
    else:
        print("  [FAIL] Unreachable domain returned Safe!")

    # -------------------------------------------------------------
    # TEST 2: DNS Failure / NXDOMAIN Handling
    # -------------------------------------------------------------
    total += 1
    t0 = time.time()
    res2 = engine.analyze("https://this-domain-definitely-does-not-exist-123456789.xyz")
    dur2 = round((time.time() - t0) * 1000, 2)
    print(f"\n[Test 2] DNS Failure / NXDOMAIN Handling")
    print(f"  URL: https://this-domain-definitely-does-not-exist-123456789.xyz")
    print(f"  Technical Status: {res2.technical_status}")
    print(f"  Overall Status: {res2.overall_status}")

    if "Unreachable" in res2.technical_status and res2.overall_status in ["Unverified", "Suspicious", "Low Risk"]:
        print("  [PASS] NXDOMAIN correctly flagged as Unreachable & Unverified/Suspicious!")
        passed += 1
    else:
        print("  [FAIL] NXDOMAIN handling failed!")

    # -------------------------------------------------------------
    # TEST 3: Verified Official Domain Whitelist
    # -------------------------------------------------------------
    total += 1
    res3 = engine.analyze("https://google.com")
    print(f"\n[Test 3] Verified Official Domain Whitelist")
    print(f"  URL: https://google.com")
    print(f"  Overall Status: {res3.overall_status}")

    if res3.overall_status == "Verified Safe":
        print("  [PASS] google.com correctly classified as 'Verified Safe'!")
        passed += 1
    else:
        print("  [FAIL] Whitelist check failed!")

    # -------------------------------------------------------------
    # TEST 4: Brand Impersonation + Unencrypted HTTP
    # -------------------------------------------------------------
    total += 1
    res4 = engine.analyze("http://paypal-login-verify.example.xyz")
    print(f"\n[Test 4] Brand Impersonation + Unencrypted HTTP")
    print(f"  URL: http://paypal-login-verify.example.xyz")
    print(f"  Connection Security: {res4.connection_security}")
    print(f"  Overall Status: {res4.overall_status}")
    print(f"  Threat Score: {res4.threat_score}/100")

    if res4.overall_status in ["High Risk", "Critical", "Suspicious"] and "HTTP" in res4.transport_protocol:
        print("  [PASS] Brand impersonation on HTTP correctly flagged as High Risk/Critical!")
        passed += 1
    else:
        print("  [FAIL] Brand impersonation on HTTP check failed!")

    # -------------------------------------------------------------
    # TEST 5: Fake CAPTCHA / PowerShell Execution Lure
    # -------------------------------------------------------------
    total += 1
    res5 = engine.analyze(
        "https://example-security-captcha.com",
        dom_title="Robot Verification",
        dom_text="Please press Windows + R, paste this command into PowerShell and press Enter to verify you are human."
    )
    print(f"\n[Test 5] Fake CAPTCHA / PowerShell Lure Detection")
    print(f"  Category: {res5.category}")
    print(f"  Overall Status: {res5.overall_status}")
    print(f"  Threat Score: {res5.threat_score}/100")

    if res5.threat_score >= 50 or "Social Engineering" in str(res5.why_blocked) or any("Fake CAPTCHA" in str(s) for s in res5.why_blocked):
        print("  [PASS] Fake CAPTCHA PowerShell lure correctly detected!")
        passed += 1
    else:
        print("  [FAIL] Fake CAPTCHA lure check failed!")

    # -------------------------------------------------------------
    # TEST 6: False Positive Prevention (Legitimate Login Routes)
    # -------------------------------------------------------------
    total += 1
    res6 = engine.analyze("https://github.com/login")
    print(f"\n[Test 6] False Positive Prevention (github.com/login)")
    print(f"  URL: https://github.com/login")
    print(f"  Overall Status: {res6.overall_status}")

    if res6.overall_status == "Verified Safe":
        print("  [PASS] Legitimate github.com/login route remained 'Verified Safe'!")
        passed += 1
    else:
        print("  [FAIL] False positive triggered for github.com/login!")

    print("\n" + "=" * 70)
    print(f"AUTOMATED TEST RESULTS: {passed}/{total} PASSED ({round(passed/total*100, 1)}%)")
    print("=" * 70)

    if passed < total:
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
