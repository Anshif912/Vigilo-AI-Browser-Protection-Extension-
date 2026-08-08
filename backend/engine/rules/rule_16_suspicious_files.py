from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

SUSPICIOUS_EXTENSIONS = {".php", ".asp", ".aspx", ".cgi", ".zip", ".exe", ".scr", ".msi", ".iso", ".bat", ".cmd", ".vbs", ".ps1", ".js"}
MALWARE_PAYLOAD_EXTS = {".exe", ".scr", ".msi", ".iso", ".bat", ".cmd", ".vbs", ".ps1"}

class Rule16SuspiciousFiles(BaseRule):
    rule_id = "RULE_16"
    rule_name = "Suspicious File Extension & Executable Detection"
    category = "Malware Download Risk"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        psl = payload.get("psl", {})
        path = psl.get("path", "").lower()
        query = psl.get("query", "").lower()
        full_url = payload.get("normalized_url", "").lower()

        target_text = f"{path}?{query}"

        has_threat_context = payload.get("has_threat_context", False)

        for ext in MALWARE_PAYLOAD_EXTS:
            if ext in target_text or ext in full_url:
                return RuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    matched=True,
                    weight=30,
                    evidence=f"Possible Malware Download Payload extension '{ext}' in URL string ({target_text})",
                    severity="CRITICAL",
                    category=self.category,
                    details={"extension": ext, "target": target_text, "is_malware_payload": True}
                )

        # Web script extensions (.aspx, .asp, .php, .cgi) only trigger if combined with active threat context
        if has_threat_context:
            for ext in {".php", ".asp", ".aspx", ".cgi"}:
                if ext in target_text or ext in full_url:
                    return RuleResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        matched=True,
                        weight=15,
                        evidence=f"Script extension '{ext}' used in combination with brand impersonation or credential harvesting context ({target_text})",
                        severity="MEDIUM",
                        category="Structural Analysis",
                        details={"extension": ext, "target": target_text, "is_malware_payload": False}
                    )

        return RuleResult(self.rule_id, self.rule_name, False, 0, "No suspicious executable file extension", "INFO", self.category)
