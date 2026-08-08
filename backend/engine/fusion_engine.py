import time
import hashlib
import json
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
from engine.connection_security import ConnectionSecurityEngine
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
            Rule21BrowserSecurityInterstitial()
        ]

    def analyze(self, raw_url: str, html_content: str = None, dom_title: str = None, dom_text: str = None) -> AnalyzeResponse:
        t0 = time.time()
        
        payload: Dict[str, Any] = {
            "raw_url": raw_url,
            "html_content": html_content,
            "dom_title": dom_title,
            "dom_text": dom_text
        }

        matched_rules = []
        all_rule_results = []
        analysis_trace = []
        score_breakdown = []

        # 1. Run Pipeline Rules
        for rule in self.rules:
            payload["has_threat_context"] = any(r.rule_id in ["RULE_03", "RULE_06", "RULE_07", "RULE_08", "RULE_09", "RULE_13"] for r in matched_rules)
            res = rule.evaluate(payload)
            all_rule_results.append(res)
            
            # Feed state updates to subsequent rules
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

        # 2. Extract Key State Variables
        psl = payload.get("psl", {})
        registered_domain = psl.get("registered_domain", raw_url.split("/")[0]).lower()
        subdomain = psl.get("subdomain", "")
        tld = psl.get("tld", "")
        hostname = psl.get("hostname", "")

        # Detect Target Brand from matched rules
        detected_brand = "Unrecognized Entity"
        brand_rule = next((r for r in matched_rules if "brand" in r.details), None)
        if brand_rule:
            detected_brand = brand_rule.details.get("brand", "Unrecognized Entity")

        # Allowlist Evaluation
        is_allowlisted = registered_domain in TRUSTED_DOMAIN_ALLOWLIST

        # Check if Rule 21 (Upstream Browser Warning Interstitial) matched
        rule_21_match = next((r for r in matched_rules if r.rule_id == "RULE_21"), None)

        if rule_21_match:
            total_score = 100
            status = "Critical"
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
            reasoning_summary = "Browser vendor or upstream security provider has identified this page as malicious or deceptive."
        elif is_allowlisted:
            total_score = 5
            status = "Safe"
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
            # Sum Matched Weights
            raw_score = sum(r.weight for r in matched_rules)
            signal_count = len(matched_rules)

            # Assign Severity & Status
            if raw_score >= 70:
                status = "Critical" if raw_score >= 75 else "High Risk"
                total_score = min(raw_score, 98)
            elif raw_score >= 40:
                status = "Suspicious" if raw_score < 60 else "High Risk"
                total_score = raw_score
            elif raw_score >= 20:
                status = "Low Risk"
                total_score = raw_score
            else:
                status = "Safe"
                total_score = min(raw_score, 15)

            # Confidence Level
            if signal_count >= 3:
                confidence = 94
                confidence_level = "High"
            elif signal_count >= 2:
                confidence = 86
                confidence_level = "High"
            elif signal_count == 1:
                confidence = 78
                confidence_level = "Medium"
            else:
                confidence = 80
                confidence_level = "Medium"

            # Categorization & Sub-Category
            has_malware_download = any(r.details and r.details.get("is_malware_payload") for r in matched_rules)
            has_subdomain_imp = any(r.rule_id == "RULE_06" for r in matched_rules)
            has_path_imp = any(r.rule_id == "RULE_07" for r in matched_rules)
            has_query_imp = any(r.rule_id == "RULE_08" for r in matched_rules)
            has_typo = any(r.rule_id in ["RULE_04", "RULE_05", "RULE_12"] for r in matched_rules)
            has_cred = any(r.rule_id in ["RULE_09", "RULE_18"] for r in matched_rules)

            if status == "Safe":
                category = "Legitimate Domain"
                sub_category = "Legitimate Unknown Domain"
                attack_type = "No Threat Detected"
                website_identity = detected_brand if detected_brand != "Unrecognized Entity" else "Clean Host"
            else:
                if has_malware_download:
                    category = "Malware Payload"
                    sub_category = "Malware Download Risk"
                    attack_type = "Malicious File Payload"
                else:
                    category = "Credential Phishing" if has_cred else "Brand Abuse"
                    if has_path_imp:
                        sub_category = "Path Brand Impersonation"
                        attack_type = "Credential Harvesting" if has_cred else "Brand Abuse"
                    elif has_query_imp:
                        sub_category = "Query Brand Abuse"
                        attack_type = "Deceptive Brand Abuse"
                    elif has_subdomain_imp:
                        sub_category = "Subdomain Impersonation"
                        attack_type = "Deceptive Brand Abuse"
                    elif has_typo:
                        sub_category = "Typosquatting Form"
                        attack_type = "Deceptive Brand Abuse"
                    else:
                        sub_category = "Phishing Portal"
                        attack_type = "Credential Harvesting"
                website_identity = detected_brand if detected_brand != "Unrecognized Entity" else registered_domain.split(".")[0].capitalize()

            reasoning_summary = f"This domain '{registered_domain}' was classified as {status} (Threat Score: {total_score}/100, Confidence: {confidence}% {confidence_level}). Multi-factor evidence alignment across {signal_count} independent detection rules."

        # 4. Telemetry Payloads & Fingerprint
        duration_ms = round((time.time() - t0) * 1000, 2)
        fingerprint_input = f"{registered_domain}:{status}:{total_score}:{category}"
        threat_fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]

        analysis_id = f"anl_v3_{hashlib.md5(raw_url.encode()).hexdigest()[:12]}"

        matched_kws = []
        for r in matched_rules:
            if r.details and "matched_keywords" in r.details:
                matched_kws.extend(r.details["matched_keywords"])

        ioc_payload = {
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "tld": tld,
            "hostname": hostname,
            "brand": website_identity,
            "keywords": list(set(matched_kws)),
            "fingerprint": threat_fingerprint,
            "matched_rules_count": len(matched_rules)
        }

        structured_evidence = {
            "matched_rules": [r.to_dict() for r in matched_rules],
            "total_rules_evaluated": len(self.rules),
            "execution_time_ms": duration_ms
        }

        why_blocked = [r.evidence for r in matched_rules] if matched_rules else ["No threat rules triggered."]
        info_at_risk = ["User Credentials", "Session Tokens"] if status in ["Critical", "High Risk", "Suspicious"] else []

        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        threat_timeline = [
            {"event": "Navigation Intercepted", "actor": "Browser Protection Engine", "timestamp": now_str},
            {"event": "PSL Domain Extracted", "actor": "PSL Parser (Rule 02)", "timestamp": now_str},
            {"event": "Brand Intelligence Search", "actor": "Brand KB (Rule 03)", "timestamp": now_str},
            {"event": "Rule Engine Fusion", "actor": "Threat Intelligence Decision Engine v3.0", "timestamp": now_str},
            {"event": f"Verdict Rendered ({status} - Score: {total_score})", "actor": "Vigilo Core", "timestamp": now_str}
        ]

        # 5. Connection Security Engine Analysis
        conn_res = ConnectionSecurityEngine.analyze_connection(raw_url, status)

        partial_response = {
            "url": raw_url,
            "status": status,
            "threat_score": total_score,
            "confidence": confidence,
            "confidence_level": confidence_level,
            "website_identity": website_identity,
            "category": category,
            "sub_category": sub_category,
            "connection_security": conn_res["connection_security"],
            "transport_protocol": conn_res["transport_protocol"],
            "structured_evidence": structured_evidence,
            "ioc": ioc_payload
        }
        ai_exp = AIExplanationGenerator.generate(partial_response)

        return AnalyzeResponse(
            url=raw_url,
            status=status,
            threat_score=total_score,
            confidence=confidence,
            confidence_level=confidence_level,
            website_identity=website_identity,
            attack_type=attack_type,
            category=category,
            sub_category=sub_category,
            reason=f"Vigilo Decision Engine evaluated {registered_domain} across {len(self.rules)} rules. Triggered {len(matched_rules)} threat signals.",
            risk_reasoning_summary=ai_exp["ai_explanation_summary"],
            information_at_risk=ai_exp["information_at_risk_details"]["items"],
            why_blocked=why_blocked,
            recommended_action=ai_exp["dynamic_recommendations"][0] if ai_exp["dynamic_recommendations"] else "Direct browser to official portal.",
            analysis_id=analysis_id,
            timestamp=now_str,
            score_breakdown=score_breakdown,
            structured_evidence=structured_evidence,
            ioc=ioc_payload,
            analysis_trace=analysis_trace,
            data_provenance={"engine": "Enterprise Threat Intelligence Decision Engine v3.2"},
            threat_fingerprint=threat_fingerprint,
            performance={"total_ms": duration_ms},
            connection_security=conn_res["connection_security"],
            transport_protocol=conn_res["transport_protocol"],
            tls_status=conn_res["tls_status"],
            security_reason=conn_res["security_reason"],
            overall_status=conn_res["overall_status"],
            ai_explanation=ai_exp,
            engine_version="3.2.0",
            feature_schema="3.2",
            brand_db_version="2026.07",
            external_threat_intel={},
            threat_timeline=threat_timeline
        )
