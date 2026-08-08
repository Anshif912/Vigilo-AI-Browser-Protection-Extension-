import urllib.parse
import unicodedata
import re
from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

class Rule01Normalization(BaseRule):
    rule_id = "RULE_01"
    rule_name = "URL Normalization"
    category = "Structural Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        raw_url = payload.get("raw_url", "")
        
        # 1. Lowercase
        normalized = raw_url.lower().strip()
        
        # 2. Remove fragments
        if "#" in normalized:
            normalized = normalized.split("#")[0]
            
        # 3. Decode URL encoding
        try:
            normalized = urllib.parse.unquote(normalized)
        except Exception:
            pass

        # 4. Normalize unicode
        normalized = unicodedata.normalize("NFKC", normalized)
        
        # 5. Remove duplicate slashes in path (preserving http:// or https://)
        if "://" in normalized:
            scheme, rest = normalized.split("://", 1)
            rest = re.sub(r"/+", "/", rest)
            normalized = f"{scheme}://{rest}"
        else:
            normalized = re.sub(r"/+", "/", normalized)

        matched = (normalized != raw_url)
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            weight=0,
            evidence=f"Normalized URL: {normalized}",
            severity="INFO",
            category=self.category,
            details={"normalized_url": normalized}
        )
