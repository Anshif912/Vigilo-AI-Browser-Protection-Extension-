from typing import Dict, Any
import pandas as pd

# Mapping dictionary from PhiUSIIL column names to Vigilo schema names
COLUMN_MAP: Dict[str, str] = {
    # URL Features
    "URLLength": "url_length",
    "DomainLength": "domain_length",
    "TLDLength": "tld_length",
    "NoOfSubDomain": "subdomain_count",
    "IsDomainIP": "is_domain_ip",
    "HasObfuscation": "has_obfuscation",
    "NoOfObfuscatedChar": "obfuscated_char_count",
    "ObfuscationRatio": "obfuscation_ratio",
    "NoOfLettersInURL": "letters_count_in_url",
    "LetterRatioInURL": "letter_ratio_in_url",
    "NoOfDegitsInURL": "digits_count_in_url",
    "DegitRatioInURL": "digit_ratio_in_url",
    "NoOfEqualsInURL": "equals_count_in_url",
    "NoOfQMarkInURL": "qmark_count_in_url",
    "NoOfAmpersandInURL": "ampersand_count_in_url",
    "NoOfOtherSpecialCharsInURL": "other_special_chars_count_in_url",
    "SpacialCharRatioInURL": "special_char_ratio_in_url",
    "IsHTTPS": "is_https",
    "CharContinuationRate": "char_continuation_rate",
    "TLDLegitimateProb": "tld_legitimate_prob",
    "URLCharProb": "url_char_prob",
    
    # DOM Features
    "LineOfCode": "line_of_code",
    "LargestLineLength": "largest_line_length",
    "HasTitle": "has_title",
    "DomainTitleMatchScore": "domain_title_match_score",
    "URLTitleMatchScore": "url_title_match_score",
    "HasFavicon": "has_favicon",
    "Robots": "robots",
    "IsResponsive": "is_responsive",
    "NoOfURLRedirect": "url_redirect_count",
    "NoOfSelfRedirect": "self_redirect_count",
    "HasDescription": "has_description",
    "NoOfPopup": "popup_count",
    "NoOfiFrame": "iframe_count",
    "HasExternalFormSubmit": "has_external_form_submit",
    "HasSocialNet": "has_social_net",
    "HasSubmitButton": "has_submit_button",
    "HasHiddenFields": "has_hidden_fields",
    "HasPasswordField": "has_password_field",
    "Bank": "bank_keyword_count",
    "Pay": "pay_keyword_count",
    "Crypto": "crypto_keyword_count",
    "HasCopyrightInfo": "has_copyright_info",
    "NoOfImage": "image_count",
    "NoOfCSS": "css_count",
    "NoOfJS": "js_count",
    "NoOfSelfRef": "self_ref_count",
    "NoOfEmptyRef": "empty_ref_count",
    "NoOfExternalRef": "external_ref_count"
}

def adapt_dataset_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Renames columns from PhiUSIIL naming scheme to Vigilo standardized names.
    Also handles non-mapped features as unavailable or drops them.
    """
    # 1. Reject target leakage and identifier columns
    rejected_columns = ["URLSimilarityIndex", "FILENAME"]
    df_clean = df.drop(columns=[col for col in rejected_columns if col in df.columns], errors="ignore")
    
    # 2. Map the columns
    rename_dict = {orig: target for orig, target in COLUMN_MAP.items() if orig in df_clean.columns}
    df_mapped = df_clean.rename(columns=rename_dict)
    
    return df_mapped
