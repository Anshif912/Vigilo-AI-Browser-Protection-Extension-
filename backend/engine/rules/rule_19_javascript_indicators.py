from typing import Dict, Any
from engine.base_rule import BaseRule, RuleResult

JS_PATTERNS = ["eval(", "document.write(", "window.location", "atob(", "unescape(", "string.fromcharcode("]
COOKIE_THEFT_PATTERNS = ["document.cookie", "localstorage", "sessionstorage", "navigator.credentials"]
CLIPBOARD_PATTERNS = ["navigator.clipboard", "writeText(", "readText("]
FAKE_CAPTCHA_PATTERNS = ["verify you're human", "verify you are human", "windows + r", "powershell", "cmd.exe"]

class Rule19JavaScriptIndicators(BaseRule):
    rule_id = "RULE_19"
    rule_name = "JavaScript Behavioral & Session Indicators"
    category = "Behavioral Analysis"

    def evaluate(self, payload: Dict[str, Any]) -> RuleResult:
        html = payload.get("html_content")
        if not html:
            return RuleResult(self.rule_id, self.rule_name, False, 0, "No HTML DOM payload provided", "INFO", self.category)

        html_lower = html.lower()
        matched_js = [pat for pat in JS_PATTERNS if pat in html_lower]
        matched_cookie = [pat for pat in COOKIE_THEFT_PATTERNS if pat in html_lower]
        matched_clipboard = [pat for pat in CLIPBOARD_PATTERNS if pat in html_lower]
        matched_captcha = [pat for pat in FAKE_CAPTCHA_PATTERNS if pat in html_lower]

        threats = []
        weight = 0

        if matched_cookie:
            threats.append(f"Cookie/Session Theft Scripts ({matched_cookie})")
            weight += 20
        if matched_clipboard:
            threats.append(f"Clipboard Hijacking & Crypto Stealer ({matched_clipboard})")
            weight += 20
        if matched_captcha:
            threats.append(f"Fake CAPTCHA / PowerShell Execution Lure ({matched_captcha})")
            weight += 30
        if matched_js:
            threats.append(f"JS Obfuscation ({matched_js})")
            weight += 15

        matched = len(threats) > 0
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            weight=min(weight, 30),
            evidence="; ".join(threats) if matched else "No suspicious JS behavioral indicators",
            severity="CRITICAL" if weight >= 25 else ("HIGH" if matched else "INFO"),
            category=self.category,
            details={
                "obfuscation": matched_js,
                "cookie_theft": matched_cookie,
                "clipboard_hijack": matched_clipboard,
                "fake_captcha": matched_captcha
            }
        )
