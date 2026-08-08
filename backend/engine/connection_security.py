import urllib.parse
from typing import Dict, Any, Tuple

class ConnectionSecurityEngine:
    @staticmethod
    def analyze_connection(url: str, threat_status: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        scheme = parsed.scheme.lower()
        
        is_https = (scheme == "https")
        
        if is_https:
            connection_security = "Secure"
            transport_protocol = "HTTPS"
            tls_status = "TLS 1.3 / Enabled"
            if threat_status in ["Safe"]:
                security_reason = "Connection is encrypted via HTTPS with zero threat indicators detected."
            else:
                security_reason = "Connection is encrypted via HTTPS, but the website exhibits active threat indicators."
        else:
            connection_security = "Not Secure"
            transport_protocol = "HTTP"
            tls_status = "Disabled"
            if threat_status in ["Safe"]:
                security_reason = "No phishing indicators detected, however the website is using an insecure HTTP connection."
            else:
                security_reason = "Website uses an unencrypted HTTP connection with active threat indicators."

        # Compute Overall Status
        if threat_status in ["Critical"]:
            overall_status = "Critical"
        elif threat_status in ["High Risk"]:
            overall_status = "High Risk"
        elif threat_status in ["Suspicious"]:
            overall_status = "Suspicious"
        elif not is_https:
            overall_status = "Low Risk"  # Never show pure Safe for HTTP!
        elif threat_status == "Low Risk":
            overall_status = "Low Risk"
        else:
            overall_status = "Safe"

        return {
            "connection_security": connection_security,
            "transport_protocol": transport_protocol,
            "tls_status": tls_status,
            "security_reason": security_reason,
            "overall_status": overall_status
        }
