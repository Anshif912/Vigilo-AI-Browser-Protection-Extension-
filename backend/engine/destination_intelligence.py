import socket
import ssl
import urllib.parse
import urllib.request
import time
from typing import Dict, Any, List

class DestinationIntelligenceEngine:
    @staticmethod
    def analyze_destination(raw_url: str) -> Dict[str, Any]:
        """
        Evaluates technical reachability, DNS resolution, HTTP status, TLS cert, and redirect chain.
        """
        parsed = urllib.parse.urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        hostname = parsed.hostname or raw_url.split('/')[0].split(':')[0]
        port = parsed.port or (443 if scheme == "https" else 80)

        result: Dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "scheme": scheme,
            "dns_status": "UNKNOWN",
            "ip_addresses": [],
            "reachable": False,
            "http_status": None,
            "technical_status": "Unverified",
            "connection_security": "HTTP Insecure" if scheme == "http" else "HTTPS Configured",
            "tls_status": "Disabled" if scheme == "http" else "Enabled",
            "tls_valid": False,
            "tls_details": {},
            "redirect_chain": [raw_url],
            "final_url": raw_url,
            "has_cross_domain_redirect": False,
            "has_protocol_downgrade": False,
            "error_reason": None
        }

        if not hostname:
            result["technical_status"] = "Invalid Hostname"
            result["error_reason"] = "No valid hostname could be extracted from URL."
            return result

        # 1. DNS Resolution Check
        try:
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set([item[4][0] for item in addr_info if item[4]]))
            result["ip_addresses"] = ips
            if ips:
                result["dns_status"] = "RESOLVED"
                result["reachable"] = True
                result["technical_status"] = "Reachable"
            else:
                result["dns_status"] = "NXDOMAIN"
                result["technical_status"] = "Unreachable / DNS Failure"
                result["error_reason"] = f"DNS resolution failed for hostname '{hostname}'."
                return result
        except socket.gaierror as e:
            result["dns_status"] = "NXDOMAIN"
            result["technical_status"] = "Unreachable / DNS Failure"
            result["error_reason"] = f"DNS resolution failed for {hostname}: {str(e)}"
            return result
        except socket.timeout:
            result["dns_status"] = "TIMEOUT"
            result["technical_status"] = "Connection Timeout"
            result["error_reason"] = f"DNS request timed out for {hostname}."
            return result
        except Exception as e:
            result["dns_status"] = "FAILED"
            result["technical_status"] = "DNS Error"
            result["error_reason"] = f"DNS lookup error: {str(e)}"
            return result

        # 2. TLS Certificate Inspection for HTTPS
        if scheme == "https":
            try:
                context = ssl.create_default_context()
                context.timeout = 2.0
                with socket.create_connection((hostname, port), timeout=2.0) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        result["tls_valid"] = True
                        result["tls_status"] = "TLS 1.3 / Valid Certificate"
                        result["connection_security"] = "HTTPS Secure"
                        if cert:
                            subject = dict(x[0] for x in cert.get('subject', ()))
                            issuer = dict(x[0] for x in cert.get('issuer', ()))
                            result["tls_details"] = {
                                "commonName": subject.get('commonName', ''),
                                "issuer": issuer.get('organizationName', issuer.get('commonName', '')),
                                "notAfter": cert.get('notAfter', '')
                            }
            except ssl.SSLCertVerificationError as e:
                result["tls_valid"] = False
                result["tls_status"] = "Certificate Error"
                result["connection_security"] = "HTTPS Cert Invalid"
                result["error_reason"] = f"TLS certificate verification failed: {str(e)}"
            except Exception as e:
                result["tls_valid"] = False
                result["tls_status"] = "Handshake Error"
                result["connection_security"] = "HTTPS Handshake Failed"

        # 3. HTTP Redirect & Reachability Check (Fast HEAD request with timeout)
        try:
            req = urllib.request.Request(
                raw_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VigiloThreatScanner/4.0"},
                method="HEAD"
            )
            # Custom HTTP Redirect Handler to track redirect chain
            class ChainRedirectHandler(urllib.request.HTTPRedirectHandler):
                def __init__(self):
                    self.chain = [raw_url]
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    self.chain.append(newurl)
                    return super().redirect_request(req, fp, code, msg, headers, newurl)

            redirect_handler = ChainRedirectHandler()
            opener = urllib.request.build_opener(redirect_handler)
            
            with opener.open(req, timeout=1.5) as resp:
                result["http_status"] = resp.status
                result["final_url"] = resp.geturl()
                result["redirect_chain"] = redirect_handler.chain
                result["reachable"] = True
                
                # Check for cross-domain or protocol downgrade redirects
                if len(redirect_handler.chain) > 1:
                    orig_domain = urllib.parse.urlparse(raw_url).hostname or ""
                    final_domain = urllib.parse.urlparse(resp.geturl()).hostname or ""
                    if orig_domain and final_domain and orig_domain.lower() != final_domain.lower():
                        result["has_cross_domain_redirect"] = True
                    
                    if raw_url.startswith("https://") and resp.geturl().startswith("http://"):
                        result["has_protocol_downgrade"] = True
        except Exception:
            # HEAD failover to GET or graceful silent catch
            pass

        return result
