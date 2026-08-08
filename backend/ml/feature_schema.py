import json
import os
from typing import List, Dict, Any

# 1. Independent Domain Features
DOMAIN_FEATURES: List[str] = [
    "domain_length",
    "subdomain_count",
    "is_domain_ip",
    "domain_letters_count",
    "domain_letter_ratio",
    "domain_digits_count",
    "domain_digit_ratio",
    "domain_special_chars_count",
    "domain_special_char_ratio",
    "domain_entropy",
    "punycode_indicator",
    "domain_has_hyphen",
    "domain_has_digits",
    "tld_length",
    "tld_legitimate_prob",
    "brand_impersonation_in_subdomain",
    "phishing_keyword_in_domain",
    "brand_impersonation_in_domain",
    "domain_hyphen_count"
]

# 2. Independent Path Features
PATH_FEATURES: List[str] = [
    "path_length",
    "path_depth",
    "path_letters_count",
    "path_digits_count",
    "path_special_chars_count",
    "path_entropy",
    "credential_keyword_in_path",
    "brand_keyword_in_path"
]

# 3. Independent Query Features
QUERY_FEATURES: List[str] = [
    "query_length",
    "query_parameter_count",
    "query_letters_count",
    "query_digits_count",
    "query_special_chars_count",
    "query_entropy",
    "redirect_parameter_in_query",
    "external_url_parameter_in_query",
    "credential_parameter_in_query",
    "brand_keyword_in_query"
]

# 4. Global URL Context
GLOBAL_FEATURES: List[str] = [
    "is_https"
]

# Combined URL-only features
URL_FEATURES: List[str] = DOMAIN_FEATURES + PATH_FEATURES + QUERY_FEATURES + GLOBAL_FEATURES

# 5. Webpage DOM-only features (remains independent)
DOM_FEATURES: List[str] = [
    "line_of_code",
    "largest_line_length",
    "has_title",
    "domain_title_match_score",
    "url_title_match_score",
    "has_favicon",
    "robots",
    "is_responsive",
    "url_redirect_count",
    "self_redirect_count",
    "has_description",
    "popup_count",
    "iframe_count",
    "has_external_form_submit",
    "has_social_net",
    "has_submit_button",
    "has_hidden_fields",
    "has_password_field",
    "bank_keyword_count",
    "pay_keyword_count",
    "crypto_keyword_count",
    "has_copyright_info",
    "image_count",
    "css_count",
    "js_count",
    "self_ref_count",
    "empty_ref_count",
    "external_ref_count"
]

# Full feature list for URL+DOM
ALL_FEATURES: List[str] = URL_FEATURES + DOM_FEATURES

# Define TLD encoding configuration
TLD_CATEGORIES = [
    "com", "org", "net", "de", "co.uk", "cn", "ru", "gq", "cf", "ga", "ml", "tk", "xyz", "top", "online", "other"
]

def get_feature_schema_metadata() -> Dict[str, Any]:
    return {
        "version": "4.2.0",
        "domain_features": DOMAIN_FEATURES,
        "path_features": PATH_FEATURES,
        "query_features": QUERY_FEATURES,
        "global_features": GLOBAL_FEATURES,
        "url_features": URL_FEATURES,
        "dom_features": DOM_FEATURES,
        "all_features": ALL_FEATURES,
        "tld_categories": TLD_CATEGORIES,
        "excluded_features": ["URLSimilarityIndex", "FILENAME", "label", "url_char_prob", "char_continuation_rate"],
        "description": "Canonical separated features for VIGILO ML Phishing Classifier"
    }

def save_schema_to_json(target_dir: str):
    os.makedirs(target_dir, exist_ok=True)
    meta = get_feature_schema_metadata()
    path = os.path.join(target_dir, "feature_schema.json")
    with open(path, "w") as f:
        json.dump(meta, f, indent=2)
