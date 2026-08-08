import time
import hashlib
import json
import asyncio
from typing import Dict, Any, List
from models.response import AnalyzeResponse

from engine.rules.rule_01_normalization import Rule01Normalization
from engine.rules.rule_02_psl_parsing import Rule02PSLParsing
from engine.rules.rule_03_brand_intelligence import Rule03BrandIntelligence
from engine.rules.rule_04_typosquatting import Rule04Typosquatting
from engine.rules.rule_05_homograph import Rule05Homograph
from engine.rules.rule_06_subdomain_impersonation import Rule06SubdomainImpersonation
from engine.rules.rule_07_path_impersonation import Rule07PathImpersonation
from engine.rules.rule_08_query_abuse import Rule08QueryAbuse
from engine.rules.rule_09_credential_keywords import Rule09CredentialKeywords
from engine.rules.rule_10_structure import Rule10Structure
from engine.rules.rule_11_entropy import Rule11Entropy
from engine.rules.rule_12_numeric_abuse import Rule12NumericAbuse
from engine.rules.rule_13_ip_address import Rule13IPAddress
from engine.rules.rule_14_username_trick import Rule14UsernameTrick
from engine.rules.rule_15_non_standard_ports import Rule15NonStandardPorts
from engine.rules.rule_16_suspicious_files import Rule16SuspiciousFiles
from engine.rules.rule_17_high_risk_tld import Rule17HighRiskTLD
from engine.rules.rule_18_dom_forms import Rule18DOMForms
from engine.rules.rule_19_javascript_indicators import Rule19JavaScriptIndicators
from engine.rules.rule_20_external_intel import Rule20ExternalIntel
from engine.rules.rule_21_browser_interstitial import Rule21BrowserSecurityInterstitial
from engine.rules.rule_22_redirect_chain import Rule22RedirectChainAnalysis

from engine.destination_intelligence import DestinationIntelligenceEngine
from engine.domain_reputation_service import DomainReputationService
from engine.content_intelligence import ContentIntelligenceEngine
from engine.external_intel import EXTERNAL_INTEL_PROVIDERS
from engine.ai_explanation_generator import AIExplanationGenerator

TRUSTED_DOMAIN_ALLOWLIST = {
    "google.com", "huggingface.co", "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "live.com", "paypal.com", "amazon.com", "apple.com", "github.com", "vercel.com", "cloudflare.com",
    "sbi.co.in", "hdfcbank.com", "passportindia.gov.in", "gov.in", "gov.uk"
}

class ThreatFusionEngine:
    def __init__(self):
        self.rules = [
            Rule01Normalization(),
            Rule02PSLParsing(),
            Rule03BrandIntelligence(),
            Rule04Typosquatting(),
            Rule05Homograph(),
            Rule06SubdomainImpersonation(),
            Rule07PathImpersonation(),
            Rule08QueryAbuse(),
            Rule09CredentialKeywords(),
            Rule10Structure(),
            Rule11Entropy(),
            Rule12NumericAbuse(),
            Rule13IPAddress(),
            Rule14UsernameTrick(),
            Rule15NonStandardPorts(),
            Rule16SuspiciousFiles(),
            Rule17HighRiskTLD(),
            Rule18DOMForms(),
            Rule19JavaScriptIndicators(),
            Rule20ExternalIntel(),
            Rule21BrowserSecurityInterstitial(),
            Rule22RedirectChainAnalysis()
        ]

    def analyze(self, raw_url: str, html_content: str = None, dom_title: str = None, dom_text: str = None) -> AnalyzeResponse:
        t0 = time.time()
        
        # 1. Technical Destination Intelligence (DNS, HTTP Status, TLS, Redirect Chain)
        dest_intel = DestinationIntelligenceEngine.analyze_destination(raw_url)

        payload: Dict[str, Any] = {
            "raw_url": raw_url,
            "html_content": html_content,
            "dom_title": dom_title,
            "dom_text": dom_text,
            "destination_intel": dest_intel
        }

        matched_rules = []
        all_rule_results = []
        analysis_trace = []
        score_breakdown = []

        # 2. Run Pipeline Heuristic Rules
        for rule in self.rules:
            payload["has_threat_context"] = any(r.rule_id in ["RULE_03", "RULE_06", "RULE_07", "RULE_08", "RULE_09", "RULE_13"] for r in matched_rules)
            res = rule.evaluate(payload)
            all_rule_results.append(res)
            
            if res.rule_id == "RULE_01":
                payload["normalized_url"] = res.details.get("normalized_url", raw_url)
            elif res.rule_id == "RULE_02":
                payload["psl"] = res.details

            analysis_trace.append({
                "stage": res.rule_name,
                "status": "MATCH" if res.matched else ("PASS" if res.rule_id in ["RULE_01", "RULE_02"] else "NO_MATCH"),
                "result": res.evidence
            })

            if res.matched and res.weight > 0:
                matched_rules.append(res)
                score_breakdown.append({
                    "factor": res.rule_name,
                    "weight": res.weight,
                    "evidence": res.evidence
                })

        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", raw_url.split("/")[0]).lower()
        subdomain = psl.get("subdomain", "")
        tld = psl.get("tld", "")
        hostname = psl.get("hostname", "")

        # 3. Domain Reputation Intelligence
        rep_intel = DomainReputationService.evaluate_reputation(registered_domain, hostname, tld)

        # 4. Content & DOM Intelligence
        content_intel = ContentIntelligenceEngine.analyze_content(dom_title, dom_text, registered_domain)

        # Detect Target Brand from matched rules
        detected_brand = "Unrecognized Entity"
        brand_rule = next((r for r in matched_rules if "brand" in r.details), None)
        if brand_rule:
            detected_brand = brand_rule.details.get("brand", "Unrecognized Entity")
        elif content_intel.get("detected_brand_impersonation"):
            detected_brand = content_intel["detected_brand_impersonation"]

        # Allowlist Check
        is_allowlisted = registered_domain in TRUSTED_DOMAIN_ALLOWLIST

        # Check for Upstream Warning (Rule 21)
        rule_21_match = next((r for r in matched_rules if r.rule_id == "RULE_21"), None)

        # 5. Multi-Signal Status Model & Unverified Detection
        technical_status = dest_intel.get("technical_status", "Reachable")
        connection_security = dest_intel.get("connection_security", "HTTPS Secure")
        reputation_status = rep_intel.get("reputation_status", "Clean Reputation")

        if rule_21_match:
            threat_status = "Critical"
            overall_status = "Critical"
            total_score = 100
            confidence = 98
            confidence_level = "High"
            category = "Browser Security Warning"
            sub_category = "Upstream Security Interstitial"
            attack_type = "Browser Security Warning Interstitial"
            website_identity = rule_21_match.details.get("vendor", "Upstream Security Provider")
            score_breakdown = [{
                "factor": "Upstream Security Interstitial Detection",
                "weight": 100,
                "evidence": rule_21_match.evidence
            }]
            reasoning_summary = "Upstream security provider or browser vendor has identified this page as malicious or deceptive."
        elif not dest_intel.get("reachable", True) or dest_intel.get("dns_status") in ["NXDOMAIN", "TIMEOUT", "FAILED"]:
            # DNS Failure / Unreachable Handling
            technical_status = dest_intel.get("technical_status", "Unreachable / DNS Failure")
            connection_security = "Unable to Verify"
            reputation_status = "Unverified"
            
            # Check if brand keywords or path impersonation exists on unreachable domain
            raw_score = sum(r.weight for r in matched_rules) + content_intel.get("threat_score", 0)
            if raw_score >= 40:
                threat_status = "Suspicious"
                overall_status = "Suspicious"
                total_score = min(raw_score, 65)
            else:
                threat_status = "Unverified"
                overall_status = "Unverified"
                total_score = 15

            confidence = 70
            confidence_level = "Medium"
            category = "Unreachable Destination"
            sub_category = "DNS Resolution Failure"
            attack_type = "Unverified Destination"
            website_identity = "Unverified Destination"
            reasoning_summary = f"Vigilo could not resolve DNS for '{hostname}'. Destination is unreachable and cannot be verified as trustworthy."
        elif is_allowlisted:
            technical_status = "Reachable"
            connection_security = dest_intel.get("connection_security", "HTTPS Secure")
            reputation_status = "Clean Reputation"
            threat_status = "Safe"
            overall_status = "Verified Safe"
            total_score = 5
            confidence = 98
            confidence_level = "High"
            category = "Verified Official Portal"
            sub_category = "Verified Official Infrastructure"
            attack_type = "Verified Official Domain"
            website_identity = registered_domain.split(".")[0].capitalize()
            score_breakdown = [{
                "factor": "Recognized Official Domain Match",
                "weight": 5,
                "evidence": f"Confirmed official platform infrastructure for {website_identity}"
            }]
            reasoning_summary = f"{website_identity} is a verified, official high-reputation domain platform."
        else:
            # 6. Weighted 7-Group Bounded Risk Scoring
            raw_heuristic_score = sum(r.weight for r in matched_rules)
            content_score = content_intel.get("threat_score", 0)
            rep_score = rep_intel.get("reputation_score", 0)

            total_raw = raw_heuristic_score + content_score + rep_score
            signal_count = len(matched_rules) + len(content_intel.get("signals", []))

            if total_raw >= 70:
                threat_status = "Critical" if total_raw >= 80 else "High Risk"
                overall_status = threat_status
                total_score = min(total_raw, 98)
            elif total_raw >= 40:
                threat_status = "Suspicious" if total_raw < 60 else "High Risk"
                overall_status = threat_status
                total_score = total_raw
            elif total_raw >= 20 or not raw_url.startswith("https://"):
                threat_status = "Low Risk"
                overall_status = "Low Risk"
                total_score = max(total_raw, 25)
            else:
                threat_status = "Safe"
                overall_status = "Unverified" if rep_score > 0 else "Safe"
                total_score = min(total_raw, 15)

            # Separated Confidence Scoring
            if signal_count >= 3 and dest_intel.get("reachable"):
                confidence = 94
                confidence_level = "High"
            elif signal_count >= 2:
                confidence = 86
                confidence_level = "High"
            elif signal_count == 1:
                confidence = 78
                confidence_level = "Medium"
            else:
                confidence = 70
                confidence_level = "Medium"

            category = "Credential Phishing" if any(r.rule_id in ["RULE_09", "RULE_18"] for r in matched_rules) else "Brand Abuse"
            sub_category = "Path Impersonation" if any(r.rule_id == "RULE_07" for r in matched_rules) else "Phishing Portal"
            attack_type = "Credential Harvesting" if category == "Credential Phishing" else "Deceptive Brand Abuse"
            website_identity = detected_brand if detected_brand != "Unrecognized Entity" else registered_domain.split(".")[0].capitalize()
            reasoning_summary = f"This domain '{registered_domain}' was classified as {overall_status} (Threat Score: {total_score}/100, Confidence: {confidence}% {confidence_level}). Multi-factor evidence alignment across {signal_count} detection signals."

        duration_ms = round((time.time() - t0) * 1000, 2)
        fingerprint_input = f"{registered_domain}:{overall_status}:{total_score}:{category}"
        threat_fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]
        analysis_id = f"anl_v4_{hashlib.md5(raw_url.encode()).hexdigest()[:12]}"

        ioc_payload = {
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "tld": tld,
            "hostname": hostname,
            "brand": website_identity,
            "fingerprint": threat_fingerprint,
            "matched_rules_count": len(matched_rules)
        }

        why_blocked = [r.evidence for r in matched_rules] if matched_rules else [reasoning_summary]
        info_at_risk = ["User Credentials", "Session Tokens"] if overall_status in ["Critical", "High Risk", "Suspicious"] else []

        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        threat_timeline = [
            {"event": "Navigation Intercepted", "actor": "Browser Protection Engine", "timestamp": now_str},
            {"event": "Technical DNS & TLS Check", "actor": "Destination Intelligence v4.0", "timestamp": now_str},
            {"event": "Domain & Content Analysis", "actor": "Content Intelligence v4.0", "timestamp": now_str},
            {"event": f"Verdict Rendered ({overall_status} - Score: {total_score})", "actor": "Vigilo Core", "timestamp": now_str}
        ]

        partial_response = {
            "url": raw_url,
            "status": overall_status,
            "threat_score": total_score,
            "confidence": confidence,
            "confidence_level": confidence_level,
            "website_identity": website_identity,
            "category": category,
            "sub_category": sub_category,
            "connection_security": connection_security,
            "transport_protocol": dest_intel.get("scheme", "http").upper(),
            "structured_evidence": {"matched_rules": [r.to_dict() for r in matched_rules], "execution_time_ms": duration_ms},
            "ioc": ioc_payload
        }
        ai_exp = AIExplanationGenerator.generate(partial_response)

        return AnalyzeResponse(
            analysis_id=analysis_id,
            timestamp=now_str,
            url=raw_url,
            status=overall_status,
            threat_score=total_score,
            confidence=confidence,
            confidence_level=confidence_level,
            website_identity=website_identity,
            attack_type=attack_type,
            category=category,
            sub_category=sub_category,
            reason=f"Vigilo Decision Engine evaluated {registered_domain} across 22 rules. Triggered {len(matched_rules)} threat signals.",
            risk_reasoning_summary=ai_exp["ai_explanation_summary"],
            information_at_risk=ai_exp["information_at_risk_details"]["items"],
            why_blocked=why_blocked,
            recommended_action=ai_exp["dynamic_recommendations"][0] if ai_exp["dynamic_recommendations"] else "Direct browser to official portal.",
            score_breakdown=score_breakdown,
            structured_evidence={"matched_rules": [r.to_dict() for r in matched_rules], "execution_time_ms": duration_ms},
            ioc=ioc_payload,
            technical_status=technical_status,
            connection_security=connection_security,
            reputation_status=reputation_status,
            threat_status=threat_status,
            overall_status=overall_status,
            transport_protocol=dest_intel.get("scheme", "http").upper(),
            tls_status=dest_intel.get("tls_status", "Disabled"),
            security_reason=dest_intel.get("error_reason") or reasoning_summary or "Technical analysis completed.",
            dns_details={
                "dns_status": dest_intel.get("dns_status"),
                "ip_addresses": dest_intel.get("ip_addresses"),
                "reachable": dest_intel.get("reachable")
            },
            redirect_chain=dest_intel.get("redirect_chain"),
            content_intel=content_intel,
            ai_explanation=ai_exp,
            engine_version="4.0.0",
            feature_schema="4.0",
            brand_db_version="2026.08",
            threat_timeline=threat_timeline
        )
