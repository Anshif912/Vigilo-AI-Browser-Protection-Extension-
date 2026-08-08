import urllib.parse
import re
import math
import unicodedata
import tldextract
from typing import Dict, Any, List
from bs4 import BeautifulSoup

# Character probability mapping from PhiUSIIL dataset
CHAR_PROBS = {
    'h': 0.04218, 't': 0.086288, 'p': 0.050166, 's': 0.053617, ':': 0.028414, '/': 0.068887, 
    'w': 0.073694, '.': 0.063821, 'o': 0.049496, 'u': 0.017532, 'b': 0.015803, 'a': 0.044109, 
    'n': 0.029537, 'k': 0.009824, 'm': 0.03116, 'i': 0.036146, 'c': 0.038197, '-': 0.009903, 
    'z': 0.004974, 'd': 0.01901, 'e': 0.049397, 'v': 0.008383, 'f': 0.014076, 'r': 0.031499, 
    'j': 0.00515, 'l': 0.024318, 'g': 0.015993, 'y': 0.009921, '6': 0.005022, '1': 0.006406, 
    'x': 0.00513, '0': 0.006145, '5': 0.005118, '9': 0.004113, '4': 0.005524, 'q': 0.003637, 
    '2': 0.006392, '3': 0.005763, '8': 0.004059, '?': 0.000833, '=': 0.00179, '@': 0.000207, 
    '7': 0.004789, '_': 0.000988, '%': 0.000708, '&': 0.001021, '!': 0.000006, '+': 0.000038, 
    ';': 0.000626, '#': 0.000104, '~': 0.000009, '(': 0.000013, ')': 0.000012, '[': 0.000002, 
    ']': 0.000003, '*': 0.000017, '$': 0.000004, ',': 0.000017
}

# TLD legitimate probability mapping from PhiUSIIL dataset
TLD_LEGIT_PROBS = {
    'com': 0.5229071, 'org': 0.0799628, 'net': 0.0384199, 'app': 0.001502, 'uk': 0.028555, 
    'co': 0.0059772, 'io': 0.0129268, 'de': 0.0326503, 'ru': 0.0180132, 'au': 0.0100856, 
    'dev': 0.0009613, 'top': 0.0002752, 'jp': 0.0230451, 'it': 0.012178, 'edu': 0.0115013, 
    'fr': 0.0141483, 'br': 0.0094423, 'nl': 0.0082003, 'ca': 0.0101825, 'info': 0.0075051, 
    'site': 0.0017656, 'xyz': 0.0017496, 'link': 0.0003306, 'in': 0.0050842, 'pl': 0.0069695, 
    'gov': 0.0033282, 'cf': 0.0001858, 'ga': 0.0002256, 'us': 0.0045585, 'me': 0.0036375, 
    'ml': 0.0001306, 'cn': 0.0033218, 'eu': 0.0056158, 'id': 0.0014653, 'es': 0.0064109, 
    'se': 0.0040185, 'be': 0.0033189, 'nz': 0.0019933, 'cz': 0.0036307, 'ch': 0.0049832, 
    'ro': 0.001523, 'club': 0.0006227, 'at': 0.0038776, 'za': 0.0018398, 'gr': 0.0016589, 
    'mx': 0.0017218, 'gq': 0.000053, 'page': 0.0001446, 'ie': 0.0015878, 'biz': 0.0017975
}

# Brand Domains Map for relationship check
BRAND_DOMAINS = {
    "google": ["google.com", "gmail.com", "youtube.com"],
    "paypal": ["paypal.com", "paypal-objects.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "media-amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "github": ["github.com", "githubusercontent.com"],
    "ollama": ["ollama.com"],
    "huggingface": ["huggingface.co"],
    "sbi": ["sbi.co.in", "statebankofindia.com", "sbi.co"]
}

# Phishing keywords in domain names check
PHISHING_KEYWORDS = {
    'kyc', 'update', 'portal', 'secure', 'login', 'signin', 'banking', 'verify', 
    'account', 'support', 'billing', 'invoice', 'checkout', 'payment', 'wallet',
    'security', 'confirm', 'service', 'client', 'customer', 'office', 'recovery',
    'safe', 'protect', 'refund', 'card', 'bank', 'pay'
}

def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of a given string.
    """
    if not text:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def check_brand_impersonation(part: str, registered_domain: str) -> int:
    """
    Checks if a brand keyword is present in a URL segment (subdomain/path/query)
    but the registered domain is not the official domain of that brand.
    """
    if not part:
        return 0
    part_lower = part.lower()
    for brand, domains in BRAND_DOMAINS.items():
        if brand in part_lower:
            if registered_domain not in domains:
                return 1
    return 0

def check_redirect_parameter(query: str, registered_domain: str) -> int:
    """
    Checks if query contains a redirect key pointing to an external domain URL.
    """
    if not query:
        return 0
    try:
        params = urllib.parse.parse_qs(query)
    except Exception:
        return 0
    redirect_keys = {'redirect', 'url', 'next', 'return', 'r', 'dest', 'destination', 'to', 'link', 'src'}
    for k, values in params.items():
        if k.lower() in redirect_keys:
            for v in values:
                if 'http://' in v or 'https://' in v:
                    extracted = tldextract.extract(v)
                    ext_domain = extracted.registered_domain.lower() if extracted.registered_domain else ""
                    if ext_domain and ext_domain != registered_domain:
                        return 1
    return 0

def check_external_url_parameter(query: str, registered_domain: str) -> int:
    """
    Checks if any parameter value contains an external URL.
    """
    if not query:
        return 0
    try:
        params = urllib.parse.parse_qs(query)
    except Exception:
        return 0
    for values in params.values():
        for v in values:
            if 'http://' in v or 'https://' in v:
                extracted = tldextract.extract(v)
                ext_domain = extracted.registered_domain.lower() if extracted.registered_domain else ""
                if ext_domain and ext_domain != registered_domain:
                    return 1
    return 0

def check_credential_parameter(query: str) -> int:
    """
    Checks if query key/value contains credential harvest keywords.
    """
    if not query:
        return 0
    credential_keywords = {'login', 'signin', 'password', 'passwd', 'credential', 'user', 'username', 'email', 'auth', 'verify', 'payment', 'token'}
    try:
        params = urllib.parse.parse_qs(query)
    except Exception:
        return 0
    for k, values in params.items():
        if any(cw in k.lower() for cw in credential_keywords):
            return 1
        for v in values:
            if any(cw in v.lower() for cw in credential_keywords):
                return 1
    return 0

def normalize_url(raw_url: str) -> str:
    """
    Standardized Vigilo URL normalization.
    """
    normalized = raw_url.lower().strip()
    if "#" in normalized:
        normalized = normalized.split("#")[0]
    try:
        normalized = urllib.parse.unquote(normalized)
    except Exception:
        pass
    normalized = unicodedata.normalize("NFKC", normalized)
    if "://" in normalized:
        scheme, rest = normalized.split("://", 1)
        rest = re.sub(r"/+", "/", rest)
        normalized = f"{scheme}://{rest}"
    else:
        normalized = re.sub(r"/+", "/", normalized)
    return normalized

def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts independent features partitioned into DOMAIN, PATH, and QUERY groups.
    Preserves full URL segments for context-aware machine learning.
    """
    norm_url = normalize_url(url)
    
    # 1. Parse using tldextract and urllib
    extracted = tldextract.extract(norm_url)
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
    tld = extracted.suffix.lower() if extracted.suffix else ""
    domain_name = extracted.domain.lower() if extracted.domain else ""
    registered_domain = extracted.registered_domain.lower() if extracted.registered_domain else ""
    
    try:
        parsed_url = urllib.parse.urlparse(norm_url if "://" in norm_url else "http://" + norm_url)
        netloc = parsed_url.netloc or parsed_url.path.split("/")[0]
        hostname = netloc.split(":")[0].lower()
    except Exception:
        hostname = norm_url.split("/")[0].split(":")[0].lower()
        
    is_domain_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0

    # Smart subdomain count normalization to handle Alexa crawl bias on clean domains
    if not subdomain and not is_domain_ip:
        hostname_for_letters = "www." + hostname
        subdomain_for_count = "www"
    else:
        hostname_for_letters = hostname
        subdomain_for_count = subdomain

    clean_dom = hostname_for_letters
    if hostname_for_letters.startswith("www."):
        clean_dom = hostname_for_letters[4:]
        
    domain_length = len(hostname_for_letters)
    subdomain_count = max(1, len(subdomain_for_count.split('.')) if subdomain_for_count else 0)
    
    # Domain specific character counts
    domain_letters_count = sum(c.isalpha() for c in clean_dom)
    domain_letter_ratio = domain_letters_count / domain_length if domain_length > 0 else 0.0
    domain_digits_count = sum(c.isdigit() for c in clean_dom)
    domain_digit_ratio = domain_digits_count / domain_length if domain_length > 0 else 0.0
    
    special_chars_set = set("-_.!~*'()[],;@=+$/?#[]")
    domain_special_chars_count = sum(1 for c in clean_dom if c in special_chars_set)
    domain_special_char_ratio = domain_special_chars_count / domain_length if domain_length > 0 else 0.0
    
    domain_entropy = calculate_entropy(clean_dom)
    punycode_indicator = 1 if hostname_for_letters.startswith("xn--") else 0
    domain_has_hyphen = 1 if "-" in clean_dom else 0
    domain_has_digits = 1 if any(c.isdigit() for c in clean_dom) else 0
    tld_length = len(tld)
    tld_legitimate_prob = TLD_LEGIT_PROBS.get(tld, 0.001)
    
    # Subdomain brand lookalike check
    brand_impersonation_in_subdomain = check_brand_impersonation(subdomain_for_count, registered_domain)
    
    # Brand impersonation in domain name
    brand_impersonation_in_domain = check_brand_impersonation(domain_name, registered_domain)
    # Phishing keyword in domain name
    phishing_keyword_in_domain = 1 if any(kw in domain_name for kw in PHISHING_KEYWORDS) else 0
    # Hyphen count in domain
    domain_hyphen_count = clean_dom.count('-')
    
    # Path extraction
    path_part = parsed_url.path
    if path_part.endswith("/"):
        path_part = path_part[:-1]
        
    path_length = len(path_part)
    path_depth = len([s for s in path_part.split('/') if s])
    path_letters_count = sum(c.isalpha() for c in path_part)
    path_digits_count = sum(c.isdigit() for c in path_part)
    path_special_chars_count = sum(1 for c in path_part if c in special_chars_set)
    path_entropy = calculate_entropy(path_part)
    
    # Context-aware credential/brand check in Path
    credential_keywords = {'login', 'signin', 'password', 'passwd', 'credential', 'user', 'username', 'email', 'auth', 'verify', 'payment', 'account', 'security', 'checkout'}
    credential_keyword_in_path = 1 if any(cw in path_part.lower() for cw in credential_keywords) else 0
    brand_keyword_in_path = check_brand_impersonation(path_part, registered_domain)
    
    # Query extraction
    query_part = parsed_url.query
    query_length = len(query_part)
    query_parameter_count = len(query_part.split('&')) if query_part else 0
    query_letters_count = sum(c.isalpha() for c in query_part)
    query_digits_count = sum(c.isdigit() for c in query_part)
    query_special_chars_count = sum(1 for c in query_part if c in special_chars_set and c not in ['=', '&'])
    query_entropy = calculate_entropy(query_part)
    
    # Context-aware query parameters
    redirect_parameter_in_query = check_redirect_parameter(query_part, registered_domain)
    external_url_parameter_in_query = check_external_url_parameter(query_part, registered_domain)
    credential_parameter_in_query = check_credential_parameter(query_part)
    brand_keyword_in_query = check_brand_impersonation(query_part, registered_domain)
    
    is_https = 1 if norm_url.startswith("https://") else 0

    return {
        # 1. DOMAIN Features
        "domain_length": domain_length,
        "subdomain_count": subdomain_count,
        "is_domain_ip": is_domain_ip,
        "domain_letters_count": domain_letters_count,
        "domain_letter_ratio": domain_letter_ratio,
        "domain_digits_count": domain_digits_count,
        "domain_digit_ratio": domain_digit_ratio,
        "domain_special_chars_count": domain_special_chars_count,
        "domain_special_char_ratio": domain_special_char_ratio,
        "domain_entropy": domain_entropy,
        "punycode_indicator": punycode_indicator,
        "domain_has_hyphen": domain_has_hyphen,
        "domain_has_digits": domain_has_digits,
        "tld_length": tld_length,
        "tld_legitimate_prob": tld_legitimate_prob,
        "brand_impersonation_in_subdomain": brand_impersonation_in_subdomain,
        "phishing_keyword_in_domain": phishing_keyword_in_domain,
        "brand_impersonation_in_domain": brand_impersonation_in_domain,
        "domain_hyphen_count": domain_hyphen_count,
        
        # 2. PATH Features
        "path_length": path_length,
        "path_depth": path_depth,
        "path_letters_count": path_letters_count,
        "path_digits_count": path_digits_count,
        "path_special_chars_count": path_special_chars_count,
        "path_entropy": path_entropy,
        "credential_keyword_in_path": credential_keyword_in_path,
        "brand_keyword_in_path": brand_keyword_in_path,
        
        # 3. QUERY Features
        "query_length": query_length,
        "query_parameter_count": query_parameter_count,
        "query_letters_count": query_letters_count,
        "query_digits_count": query_digits_count,
        "query_special_chars_count": query_special_chars_count,
        "query_entropy": query_entropy,
        "redirect_parameter_in_query": redirect_parameter_in_query,
        "external_url_parameter_in_query": external_url_parameter_in_query,
        "credential_parameter_in_query": credential_parameter_in_query,
        "brand_keyword_in_query": brand_keyword_in_query,
        
        # 4. GLOBAL Feature
        "is_https": is_https
    }

def extract_page_features(html: str, url: str) -> Dict[str, Any]:
    """
    DOM-based feature extraction matching feature_schema.py.
    """
    if not html:
        from ml.feature_schema import DOM_FEATURES
        return {f: None for f in DOM_FEATURES}
        
    soup = BeautifulSoup(html, 'html.parser')
    
    lines = html.split('\n')
    line_of_code = len(lines)
    largest_line_length = max(len(l) for l in lines) if lines else 0
    
    title_tag = soup.find('title')
    has_title = 1 if title_tag and title_tag.text.strip() else 0
    title_text = title_tag.text.lower() if has_title else ""
    
    extracted = tldextract.extract(url)
    domain_name = extracted.domain.lower() if extracted.domain else ""
    
    domain_title_match_score = 1.0 if domain_name and domain_name in title_text else 0.0
    url_title_match_score = 1.0 if url.lower() in title_text or title_text in url.lower() else 0.0
    
    has_favicon = 1 if soup.find('link', rel=re.compile(r'^(shortcut )?icon$', re.I)) else 0
    robots = 1 if soup.find('meta', attrs={'name': 'robots'}) else 0
    is_responsive = 1 if soup.find('meta', attrs={'name': 'viewport'}) else 0
    
    url_redirect_count = 0
    self_redirect_count = 0
    
    desc_tag = soup.find('meta', attrs={'name': 'description'})
    has_description = 1 if desc_tag and desc_tag.get('content') else 0
    
    popup_count = len(re.findall(r"window\.open\(|showModal\(", html))
    iframe_count = len(soup.find_all('iframe'))
    
    forms = soup.find_all('form')
    has_external_form_submit = 0
    has_submit_button = 0
    has_hidden_fields = 0
    has_password_field = 0
    
    parsed_url = urllib.parse.urlparse(url)
    base_domain = tldextract.extract(url).registered_domain
    
    for f in forms:
        action = f.get('action', '')
        if action:
            if action.startswith('http') and base_domain not in action:
                has_external_form_submit = 1
        if f.find(attrs={"type": "submit"}) or f.find('button'):
            has_submit_button = 1
        if f.find(attrs={"type": "hidden"}):
            has_hidden_fields = 1
        if f.find(attrs={"type": "password"}):
            has_password_field = 1
            
    text = soup.get_text().lower()
    bank_keyword_count = text.count('bank') + text.count('banking') + text.count('sbi') + text.count('chase')
    pay_keyword_count = text.count('pay') + text.count('payment') + text.count('paypal') + text.count('checkout')
    crypto_keyword_count = text.count('crypto') + text.count('wallet') + text.count('bitcoin') + text.count('binance')
    
    has_copyright_info = 1 if any(kw in text for kw in ['copyright', 'copy right', '©', '&copy;']) else 0
    
    image_count = len(soup.find_all('img'))
    css_count = len(soup.find_all('link', rel='stylesheet')) + len(soup.find_all('style'))
    js_count = len(soup.find_all('script'))
    
    links = soup.find_all('a')
    self_ref_count = 0
    empty_ref_count = 0
    external_ref_count = 0
    
    for l in links:
        href = l.get('href', '').strip()
        if not href or href == '#' or href.startswith('javascript:'):
            empty_ref_count += 1
        elif href.startswith('/') or (base_domain and base_domain in href):
            self_ref_count += 1
        else:
            external_ref_count += 1
            
    return {
        "line_of_code": line_of_code,
        "largest_line_length": largest_line_length,
        "has_title": has_title,
        "domain_title_match_score": domain_title_match_score,
        "url_title_match_score": url_title_match_score,
        "has_favicon": has_favicon,
        "robots": robots,
        "is_responsive": is_responsive,
        "url_redirect_count": url_redirect_count,
        "self_redirect_count": self_redirect_count,
        "has_description": has_description,
        "popup_count": popup_count,
        "iframe_count": iframe_count,
        "has_external_form_submit": has_external_form_submit,
        "has_social_net": 1 if any(soc in text for soc in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com']) else 0,
        "has_submit_button": has_submit_button,
        "has_hidden_fields": has_hidden_fields,
        "has_password_field": has_password_field,
        "bank_keyword_count": bank_keyword_count,
        "pay_keyword_count": pay_keyword_count,
        "crypto_keyword_count": crypto_keyword_count,
        "has_copyright_info": has_copyright_info,
        "image_count": image_count,
        "css_count": css_count,
        "js_count": js_count,
        "self_ref_count": self_ref_count,
        "empty_ref_count": empty_ref_count,
        "external_ref_count": external_ref_count
    }
