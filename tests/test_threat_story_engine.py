import sys
import os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import json
import time
from services.threat_story import ThreatStoryEngineBackend

test_scenarios = [
    {
        "name": "Microsoft Phishing",
        "analysis": {
            "status": "Critical",
            "threat_score": 95,
            "website_identity": "Microsoft",
            "category": "Credential Phishing",
            "reason": "Brand impersonation and credential capture form targeting Microsoft accounts.",
            "information_at_risk": ["Password", "Email Account"],
            "connection_security": "Secure"
        }
    },
    {
        "name": "Google Phishing",
        "analysis": {
            "status": "High Risk",
            "threat_score": 85,
            "website_identity": "Google Account Services",
            "category": "Credential Phishing",
            "reason": "Typosquatted Google authentication portal.",
            "information_at_risk": ["Password", "Google Credentials"],
            "connection_security": "Not Secure"
        }
    },
    {
        "name": "Bank Phishing",
        "analysis": {
            "status": "Critical",
            "threat_score": 100,
            "website_identity": "State Bank of India",
            "category": "Financial Scam",
            "reason": "Fake banking gateway attempting to harvest credit card numbers and OTPs.",
            "information_at_risk": ["Bank Card", "Payment Information", "OTP"],
            "connection_security": "Not Secure"
        }
    },
    {
        "name": "Crypto Phishing",
        "analysis": {
            "status": "Critical",
            "threat_score": 98,
            "website_identity": "MetaMask Wallet",
            "category": "Crypto Theft",
            "reason": "Fake wallet connection popup asking for secret seed phrases.",
            "information_at_risk": ["Crypto Wallet", "Secret Recovery Phrase"],
            "connection_security": "Secure"
        }
    },
    {
        "name": "Browser Warning Interstitial Page",
        "analysis": {
            "status": "Critical",
            "threat_score": 100,
            "website_identity": "Reported Deceptive Site",
            "category": "Browser Security Warning",
            "reason": "Cloudflare and Google Safe Browsing warning page detected.",
            "information_at_risk": ["Password", "Personal Information"],
            "connection_security": "Not Secure"
        }
    },
    {
        "name": "Safe Website (Must return None)",
        "analysis": {
            "status": "Safe",
            "threat_score": 5,
            "website_identity": "GitHub Official",
            "category": "Legitimate Domain",
            "reason": "Verified official domain.",
            "information_at_risk": [],
            "connection_security": "Secure"
        }
    }
]

print("====================================================")
print("VIGILO v3.5 AI THREAT STORY ENGINE VERIFICATION TEST")
print("====================================================\n")

jargon_prohibited = ["DOM", "IOC", "Entropy", "PSL", "Regex", "HTML Injection", "JavaScript Redirect"]
passed_count = 0
total_scenarios = len(test_scenarios)

for i, scenario in enumerate(test_scenarios, 1):
    name = scenario["name"]
    analysis = scenario["analysis"]
    
    start_time = time.perf_counter()
    res = ThreatStoryEngineBackend.generate_story(analysis)
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000

    print(f"Scenario {i}: {name}")
    print(f"Duration: {duration_ms:.2f} ms")

    if analysis["status"] in ["Safe", "Low Risk"]:
        if res is None:
            print("  ✅ CORRECT: Returned None for Safe/Low Risk website.")
            passed_count += 1
        else:
            print("  ❌ FAIL: Story returned for Safe website!")
    else:
        if res and res.get("story_text"):
            story = res["story_text"]
            word_count = len(story.split())
            
            # Verify jargon check
            has_jargon = any(j in story for j in jargon_prohibited)
            
            print(f"  Title: {res['title']}")
            print(f"  Word Count: {word_count} words")
            print(f"  Confidence: {res['confidence']}%")
            print(f"  Potential Impact: {res['potential_impact']}")
            print(f"  Story Text:\n    \"{story}\"")

            if not has_jargon and duration_ms < 150:
                print("  ✅ PASS: Story generated naturally in <150ms without technical jargon.\n")
                passed_count += 1
            else:
                print(f"  ❌ FAIL: Jargon detected ({has_jargon}) or took >150ms ({duration_ms:.2f}ms).\n")
        else:
            print("  ❌ FAIL: Story generation returned empty for suspicious site!\n")

print(f"TOTAL PASSED: {passed_count}/{total_scenarios} ({round((passed_count/total_scenarios)*100, 2)}%)")
