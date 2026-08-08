from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult
from services.brand_database import ALL_BRAND_ENTRIES

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

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    d = {}
    len1 = len(s1)
    len2 = len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost) # transposition
    return d[(len1 - 1, len2 - 1)]

class Rule04Typosquatting(BaseRule):
    rule_id = "RULE_04"
    rule_name = "Typosquatting & Distance Metric Detection"
    category = "Typosquatting"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        registered_domain = psl.get("domain", "").lower() # e.g. "g00gle-security"
        
        if not registered_domain:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No domain to evaluate", "INFO", self.category)

        tokens = [t for t in registered_domain.split("-") if t]

        for brand in ALL_BRAND_ENTRIES:
            if len(brand) < 4:
                continue

            for token in tokens:
                if token == brand:
                    continue  # Exact match handled by Brand Intelligence

                damerau_dist = damerau_levenshtein_distance(token, brand)
                similarity = round((1 - damerau_dist / max(len(token), len(brand))) * 100, 1)

                if 0 < damerau_dist <= 2 and len(token) >= 4 and similarity >= 75.0:
                    brand_label = brand.upper() if brand in ["sbi", "hdfc", "icici"] else brand.capitalize()
                    return RuleResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        matched=True,
                        weight=30,
                        evidence=f"Typosquatting variation against '{brand_label}' (Similarity: {similarity}%, Damerau Distance: {damerau_dist})",
                        severity="HIGH",
                        category=self.category,
                        details={
                            "brand": brand_label,
                            "similarity": similarity,
                            "distance": damerau_dist,
                            "token": token
                        }
                    )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No typosquatting detected", "INFO", self.category)
