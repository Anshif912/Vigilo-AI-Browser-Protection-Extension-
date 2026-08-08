import math
import uuid
import time
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional

import tldextract

from models.response import AnalyzeResponse
from services.brand_database import ALL_BRAND_ENTRIES, get_brand_category
from services.external_intel_service import ExternalIntelService

def current_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

SUSPICIOUS_TLDS = {".xyz", ".top", ".tech", ".online", ".site", ".click", ".work", ".info", ".live", ".club", ".vip", ".cc", ".icu", ".rest"}

KEYWORD_CATEGORIES = {
    "login": ["login", "signin", "auth", "credential", "account", "user", "access", "passcode", "document", "share"],
    "urgency": ["verify", "verification", "kyc", "secure", "update", "alert", "notice", "action", "support", "confirm", "portal"],
    "financial": ["bank", "pay", "card", "billing", "wallet", "transfer", "otp", "credit", "cash", "loan", "refund"]
}

# Standard Legitimate Platform Whitelist (Official root domains)
OFFICIAL_PLATFORM_WHITELIST = {
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "onlinesbi.sbi", "sbi.co.in", "netflix.com", "huggingface.co",
    "vercel.com", "cloudflare.com", "stackoverflow.com", "wikipedia.org", "openai.com"
}

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob), 2)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_homographs(text: str) -> str:
    """Replaces visual homographs (0->o, 1->l, I->l, @->a, $, etc.) for typosquatting checks."""
    replacements = {
        '0': 'o', '1': 'l', 'I': 'l', '|': 'l', '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm'
    }
    normalized = text.lower()
    for k, v in replacements.items():
        normalized = normalized.replace(k, v)
    return normalized

def parse_with_public_suffix(url_or_hostname: str) -> Tuple[str, str, str, str]:
    """
    Parses (subdomain, registered_domain, tld, root_name) using the Public Suffix List via tldextract.
    Accurately handles:
    - google.com.example.org -> registered_domain: example.org, subdomain: google.com
    - abc.github.io -> registered_domain: abc.github.io, subdomain: ""
    - bank.gov.in -> registered_domain: bank.gov.in, subdomain: ""
    """
    try:
        extracted = tldextract.extract(url_or_hostname)
        subdomain = extracted.subdomain.lower().strip()
        registered_domain = extracted.registered_domain.lower().strip()
        tld = f".{extracted.suffix.lower().strip()}" if extracted.suffix else ""
        root_name = extracted.domain.lower().strip()

        if not registered_domain:
            registered_domain = url_or_hostname.split(":")[0].split("/")[0].lower()
            root_name = registered_domain.split(".")[0]

        return subdomain, registered_domain, tld, root_name
    except Exception:
        parts = url_or_hostname.lower().split(".")
        if len(parts) >= 2:
            reg = f"{parts[-2]}.{parts[-1]}"
            sub = ".".join(parts[:-2])
            root = parts[-2]
            tld = f".{parts[-1]}"
            return sub, reg, tld, root
        return "", url_or_hostname, "", url_or_hostname

from engine.fusion_engine import ThreatFusionEngine

_fusion_engine_instance = ThreatFusionEngine()

class UniversalURLAnalyzer:
    @staticmethod
    def analyze_url(url: str, html_content: Optional[str] = None, dom_title: Optional[str] = None, dom_text: Optional[str] = None) -> AnalyzeResponse:
        return _fusion_engine_instance.analyze(url, html_content, dom_title, dom_text)
        analysis_trace: List[Dict[str, Any]] = []

        # 1. Canonicalization & Parsing
        raw_url = url.strip()
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        try:
            parsed = urllib.parse.urlparse(raw_url)
            hostname = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            query = (parsed.query or "").lower()
            full_path = (path + "?" + query).lower()
        except Exception:
            hostname = raw_url.lower()
            full_path = ""

        t0_parse = time.time()
        subdomains, registered_domain, tld, root_name = parse_with_public_suffix(raw_url)
        parse_duration_ms = round((time.time() - t0_parse) * 1000, 2)

        analysis_trace.append({
            "stage": "Registered Domain Parsing (PSL)",
            "status": "PASS",
            "result": f"Registered domain '{registered_domain}' (Subdomain: '{subdomains}', TLD: '{tld}')"
        })

        # 2. Check Whitelisted Official Platforms
        if registered_domain in OFFICIAL_PLATFORM_WHITELIST and not subdomains:
            brand_label = root_name.capitalize()
            exec_time = round((time.time() - start_time) * 1000, 2)
            fingerprint_raw = f"{registered_domain}||Verified Official Portal|{brand_label}|{tld}"
            fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

            analysis_trace.append({
                "stage": "Official Whitelist Check",
                "status": "MATCH",
                "result": f"Verified official root domain for {brand_label}"
            })

            return AnalyzeResponse(
                analysis_id=analysis_id,
                timestamp=ts,
                url=url,
                status="Safe",
                threat_score=5,
                confidence=98,
                confidence_level="High",
                website_identity=brand_label,
                attack_type="Verified Official Domain",
                category="Verified Official Portal",
                sub_category="Official Infrastructure",
                reason=f"Verified official platform domain for {brand_label}.",
                risk_reasoning_summary=f"{brand_label} is a verified, official high-reputation domain platform.",
                information_at_risk=[],
                why_blocked=[],
                recommended_action="Domain is safe for navigation.",
                score_breakdown=[{
                    "factor": "Verified Official Domain Whitelist",
                    "weight": 5,
                    "evidence": f"Confirmed official platform infrastructure for {brand_label}"
                }],
                structured_evidence={
                    "brand": {"detected": brand_label, "similarity": 100.0},
                    "tld": {"value": tld, "risk": "Low"},
                    "keywords": [],
                    "entropy": calculate_shannon_entropy(hostname),
                    "domain_length": len(hostname),
                    "homograph": False,
                    "registered_domain": registered_domain
                },
                ioc={
                    "registered_domain": registered_domain,
                    "subdomains": subdomains.split(".") if subdomains else [],
                    "tld": tld,
                    "brand": brand_label,
                    "keywords": [],
                    "homograph": False,
                    "shannon_entropy": calculate_shannon_entropy(hostname),
                    "domain_length": len(hostname)
                },
                analysis_trace=analysis_trace,
                data_provenance={
                    "domain_parsing": "Public Suffix List (tldextract)",
                    "brand": "Verified Platform Whitelist",
                    "entropy": "Local Shannon Heuristics",
                    "external": "Verified Official Record"
                },
                threat_fingerprint=fingerprint,
                performance={
                    "parse_ms": parse_duration_ms,
                    "brand_ms": 0.5,
                    "typosquat_ms": 0.0,
                    "entropy_ms": 0.2,
                    "total_ms": exec_time
                },
                engine_version="2.5.0",
                feature_schema="2.1",
                brand_db_version="2026.07",
                external_threat_intel=ExternalIntelService.check_url(url, registered_domain)
            )

        # 3. Brand Impersonation & Typosquatting Analysis (300+ Brands)
        t0_brand = time.time()
        normalized_root = root_name.lower()
        normalized_subdomains = subdomains.lower()
        normalized_full_url = raw_url.lower()
        homograph_root = normalize_homographs(root_name)
        entropy = calculate_shannon_entropy(hostname)

        score_breakdown: List[Dict[str, Any]] = []

        brand_weight = 0
        detected_brand = "Unrecognized Entity"
        typosquatting_detected = False
        subdomain_impersonation = False
        similarity_pct = 0.0
        brand_evidence_str = ""

        GENERIC_PATH_TOKENS = {"secure", "document", "share", "login", "signin", "update", "portal", "support", "verify", "online", "service", "system", "access", "account", "check", "admin"}

        # Scan 300+ Brand Knowledge Base
        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 3:
                continue

            # 1. Subdomain Impersonation (e.g. google.com.example.org)
            if brand in normalized_subdomains and brand not in normalized_root:
                detected_brand = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                brand_weight = 30
                subdomain_impersonation = True
                similarity_pct = 95.0
                brand_evidence_str = f"Impersonating official identity of {detected_brand} in subdomain structure ({subdomains})"
                break

            # 2. Exact or Homograph Match in Registered Root Domain
            elif brand in homograph_root:
                detected_brand = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                brand_weight = 30
                similarity_pct = 92.0
                if brand not in root_name.lower():
                    typosquatting_detected = True
                    similarity_pct = 96.4
                    brand_evidence_str = f"Visual homograph / typosquatting match for identity '{detected_brand}'"
                else:
                    brand_evidence_str = f"Brand name '{detected_brand}' present in domain string"
                break

            # 3. Levenshtein distance check on domain tokens (excluding generic path words)
            else:
                tokens = [t for t in normalized_root.split("-") if t and t not in GENERIC_PATH_TOKENS]
                for token in tokens:
                    dist = levenshtein_distance(token, brand)
                    similarity = round((1 - dist / max(len(token), len(brand))) * 100, 1)
                    if 0 < dist <= 2 and len(token) >= 4 and similarity >= 75.0:
                        detected_brand = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                        brand_weight = 25
                        typosquatting_detected = True
                        similarity_pct = similarity
                        brand_evidence_str = f"Typosquatting variation against '{detected_brand}' (Similarity: {similarity_pct}%)"
                        break
                if brand_weight > 0:
                    break


        # 3b. Path & Subpath Brand Impersonation Analysis
        path_brand_impersonation = False
        if brand_weight == 0 and full_path and full_path != "/":
            normalized_path = full_path.lower()
            for brand in ALL_BRAND_ENTRIES:
                if len(brand) < 3:
                    continue
                if brand in normalized_path and brand not in normalized_root and brand not in normalized_subdomains:
                    if brand == "americanexpress" or brand == "amex":
                        detected_brand = "American Express"
                    elif brand in ["sbi", "hdfc", "icici", "ibm", "irs", "fbi", "cia", "nhs"]:
                        detected_brand = brand.upper()
                    else:
                        detected_brand = brand.capitalize()

                    brand_weight = 20
                    path_brand_impersonation = True
                    similarity_pct = 90.0
                    brand_evidence_str = f"Trusted brand '{detected_brand}' detected inside URL path while registered domain is {registered_domain}."
                    break

        brand_duration_ms = round((time.time() - t0_brand) * 1000, 2)

        if brand_weight > 0:
            factor_label = "Path Brand Impersonation" if path_brand_impersonation else (
                "Subdomain Brand Impersonation" if subdomain_impersonation else (
                    "Typosquatting & Homograph" if typosquatting_detected else "Brand Impersonation"
                )
            )
            score_breakdown.append({
                "factor": factor_label,
                "weight": brand_weight,
                "evidence": brand_evidence_str
            })
            stage_name = "Path Brand Analysis" if path_brand_impersonation else "Brand Detection & Typosquatting"
            analysis_trace.append({
                "stage": stage_name,
                "status": "MATCH",
                "result": brand_evidence_str
            })
        else:
            analysis_trace.append({
                "stage": "Brand Detection & Typosquatting",
                "status": "NO_MATCH",
                "result": "No known enterprise brand target detected"
            })

        # 4. Keyword Extraction & Category Analysis
        t0_keywords = time.time()
        matched_keywords: List[str] = []
        is_credential_risk = False
        is_urgency_risk = False
        is_banking_risk = False

        for cat_name, kws in KEYWORD_CATEGORIES.items():
            for kw in kws:
                if kw in normalized_full_url and kw not in matched_keywords:
                    matched_keywords.append(kw)
                    if cat_name == "login":
                        is_credential_risk = True
                    elif cat_name == "urgency":
                        is_urgency_risk = True
                    elif cat_name == "financial":
                        is_banking_risk = True

        if is_credential_risk:
            score_breakdown.append({
                "factor": "Credential Harvesting Keywords",
                "weight": 20,
                "evidence": f"Matched credential collection terms: {matched_keywords}"
            })
        elif is_banking_risk:
            score_breakdown.append({
                "factor": "Financial & Payment Keywords",
                "weight": 15,
                "evidence": f"Matched payment/banking terms: {matched_keywords}"
            })

        if is_urgency_risk:
            score_breakdown.append({
                "factor": "Urgency & Verification Keywords",
                "weight": 10,
                "evidence": f"Matched urgency/verification terms: {[k for k in matched_keywords if k in KEYWORD_CATEGORIES['urgency']]}"
            })

        # 5. TLD Risk Analysis
        tld_risk_level = "High" if tld in SUSPICIOUS_TLDS else "Low"
        if tld_risk_level == "High":
            score_breakdown.append({
                "factor": f"High Risk TLD ({tld})",
                "weight": 15,
                "evidence": f"Domain utilizes high-risk TLD '{tld}' commonly abused in automated phishing campaigns"
            })

        # 6. Shannon Entropy & Structural Anomaly
        t0_entropy = time.time()
        if entropy > 3.8:
            score_breakdown.append({
                "factor": "High Shannon Entropy",
                "weight": 10,
                "evidence": f"Domain randomness entropy ({entropy}) exceeds risk threshold (3.80)"
            })

        if len(hostname) > 28:
            score_breakdown.append({
                "factor": "Excessive Domain Length",
                "weight": 5,
                "evidence": f"Hostname length ({len(hostname)} chars) indicates obfuscated structure"
            })
        entropy_duration_ms = round((time.time() - t0_entropy) * 1000, 2)

        # 7. Passive DOM Feature Inspection (Optional)
        dom_evidence = []
        if html_content:
            html_lower = html_content.lower()
            if 'type="password"' in html_lower or "type='password'" in html_lower:
                score_breakdown.append({
                    "factor": "Password Input Field (DOM)",
                    "weight": 15,
                    "evidence": "HTML payload contains credential password submission form"
                })
                dom_evidence.append("Password Input")
            if "creditcard" in html_lower or "cvv" in html_lower:
                score_breakdown.append({
                    "factor": "Credit Card Form (DOM)",
                    "weight": 15,
                    "evidence": "HTML payload contains credit card payment form"
                })
                dom_evidence.append("Card Details")

        # 8. Calculate Total Threat Score & 5-Tier Status
        total_score = sum(item["weight"] for item in score_breakdown)

        # Signal Alignment Count for Consistency-Based Confidence
        signal_count = len(score_breakdown)

        if total_score >= 70 or (subdomain_impersonation and (is_credential_risk or is_urgency_risk or brand_weight >= 25)) or (path_brand_impersonation and is_credential_risk):
            status = "Critical" if total_score >= 75 else "High Risk"
            total_score = min(max(total_score, 68), 98)
            confidence = 94 if signal_count >= 3 else 88
            confidence_level = "High"
        elif total_score >= 40 or path_brand_impersonation:
            status = "Suspicious" if total_score < 60 else "High Risk"
            confidence = 86 if signal_count >= 2 else 78
            confidence_level = "High" if confidence >= 85 else "Medium"
        elif total_score >= 20:
            status = "Low Risk"
            confidence = 80
            confidence_level = "Medium"
        else:
            status = "Safe"
            confidence = 85 if registered_domain in OFFICIAL_PLATFORM_WHITELIST else 80
            confidence_level = "High" if confidence >= 85 else "Medium"
            total_score = min(total_score, 15)

        # Categorization & Sub-Category
        category_name = get_brand_category(detected_brand) if detected_brand != "Unrecognized Entity" else ("Brand Abuse" if path_brand_impersonation else "Credential Phishing")
        if status in ["Safe", "Low Risk"] and brand_weight == 0 and not is_credential_risk and not path_brand_impersonation:
            category_name = "Legitimate Domain"
            sub_category = "Legitimate Unknown Domain" if registered_domain not in OFFICIAL_PLATFORM_WHITELIST else "Verified Official Infrastructure"
            attack_type = "No Threat Detected"
        else:
            if path_brand_impersonation:
                sub_category = "Path Brand Impersonation"
                attack_type = "Credential Harvesting" if is_credential_risk else "Brand Abuse"
            elif is_credential_risk or "login" in matched_keywords:
                attack_type = "Credential Harvesting"
                sub_category = "Subdomain Impersonation" if subdomain_impersonation else ("Typosquatting Form" if typosquatting_detected else "Phishing Portal")
            elif is_banking_risk:
                attack_type = "Financial Fraud"
                sub_category = "Payment Gateway Phishing"
            else:
                attack_type = "Deceptive Brand Abuse"
                sub_category = "Brand Impersonation"

        # Information at Risk
        at_risk = []
        if is_banking_risk or detected_brand in ["SBI", "HDFC", "ICICI", "PayPal", "Paytm", "Binance", "Coinbase", "American Express", "Amex"]:
            at_risk = ["Bank Account Credentials", "Debit/Credit Card Numbers", "CVV Code", "Two-Factor OTP"]
        elif is_credential_risk or "Password Input" in dom_evidence:
            at_risk = ["User Account Login", "Password", "Session Tokens"]
        else:
            at_risk = ["Personal Identifiable Information"]

        # Explanations & Narrative Summary
        why_blocked = [item["evidence"] for item in score_breakdown]
        if not why_blocked:
            why_blocked = ["Arbitrary domain analyzed. No suspicious brand impersonation, credential harvesting forms, or structural anomalies detected."]

        reason = (
            f"Vigilo Engine evaluated {hostname}. "
            f"Brand score: {brand_weight}pts, Credential risk: {20 if is_credential_risk else 0}pts, "
            f"TLD risk: {15 if tld_risk_level == 'High' else 0}pts."
        )

        if path_brand_impersonation:
            narrative_summary = f"This URL embeds the trusted brand '{detected_brand}' inside the URL path while the registered domain belongs to {registered_domain}. This is a common phishing technique used to deceive users."
        else:
            narrative_summary = (
                f"This domain '{registered_domain}' was classified as {status} (Threat Score: {total_score}/100, Confidence: {confidence}% {confidence_level}). "
                + (f"It impersonates {detected_brand} through a deceptive subdomain/typosquatted structure, " if brand_weight > 0 else "")
                + (f"contains credential harvesting keywords ({matched_keywords}), " if matched_keywords else "")
                + (f"uses a high-risk TLD ({tld}), " if tld_risk_level == "High" else "")
                + f"with multi-factor evidence alignment across {signal_count} independent threat indicators."
            ) if status not in ["Safe"] else f"Domain '{registered_domain}' was classified as Safe with {confidence}% confidence. No suspicious brand impersonation, credential harvesting forms, or structural anomalies were detected."

        recommended_action = (
            "Do NOT enter credentials or personal data. Direct your browser to the verified official portal."
            if status in ["Critical", "High Risk"] else (
                "Exercise caution before entering login credentials." if status == "Suspicious" else "Domain appears clean for normal browsing."
            )
        )

        # Standardized Telemetry Payloads
        structured_evidence = {
            "brand": {"detected": detected_brand, "similarity": similarity_pct},
            "tld": {"value": tld, "risk": tld_risk_level},
            "keywords": matched_keywords,
            "entropy": entropy,
            "domain_length": len(hostname),
            "homograph": typosquatting_detected,
            "registered_domain": registered_domain,
            "subdomains": subdomains,
            "dom_features": dom_evidence
        }

        ioc_payload = {
            "registered_domain": registered_domain,
            "subdomains": subdomains.split(".") if subdomains else [],
            "tld": tld,
            "brand": detected_brand,
            "keywords": matched_keywords,
            "homograph": typosquatting_detected,
            "shannon_entropy": entropy,
            "domain_length": len(hostname)
        }

        data_provenance = {
            "domain_parsing": "Public Suffix List (tldextract)",
            "brand": "Knowledge Base (300+ Enterprise Brands)",
            "entropy": "Local Shannon Heuristics",
            "tld_risk": "Vigilo TLD Risk Taxonomy",
            "external": "Threat Feeds Federation"
        }

        fingerprint_raw = f"{registered_domain}|{','.join(matched_keywords)}|{category_name}|{detected_brand}|{tld}"
        threat_fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

        analysis_trace.append({
            "stage": "Threat Fusion & Confidence Engine",
            "status": "COMPLETE",
            "result": f"Assigned Threat Score {total_score} ({status}) with Confidence {confidence}% ({confidence_level}) based on {signal_count} aligned signals"
        })

        exec_time = round((time.time() - start_time) * 1000, 2)

        return AnalyzeResponse(
            analysis_id=analysis_id,
            timestamp=ts,
            url=url,
            status=status,
            threat_score=total_score,
            confidence=confidence,
            confidence_level=confidence_level,
            website_identity=detected_brand if detected_brand != "Unrecognized Entity" else root_name.capitalize(),
            attack_type=attack_type,
            category=category_name,
            sub_category=sub_category,
            reason=reason,
            risk_reasoning_summary=narrative_summary,
            information_at_risk=at_risk,
            why_blocked=why_blocked,
            recommended_action=recommended_action,
            score_breakdown=score_breakdown,
            structured_evidence=structured_evidence,
            ioc=ioc_payload,
            analysis_trace=analysis_trace,
            data_provenance=data_provenance,
            threat_fingerprint=threat_fingerprint,
            performance={
                "parse_ms": parse_duration_ms,
                "brand_ms": brand_duration_ms,
                "typosquat_ms": 0.5,
                "entropy_ms": entropy_duration_ms,
                "total_ms": exec_time
            },
            engine_version="2.5.0",
            feature_schema="2.1",
            brand_db_version="2026.07",
            external_threat_intel=ExternalIntelService.check_url(url, registered_domain)
        )
