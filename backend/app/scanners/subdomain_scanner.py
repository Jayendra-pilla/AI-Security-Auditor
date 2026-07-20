import socket
import time
import logging
from urllib.parse import urlparse
from app.observability.ssrf_prevention import SafeHTTPClient
from app.scanners.scanner_utils import datetime_now_utc_str

logger = logging.getLogger(__name__)

class SubdomainScanner:
    """
    Scanner to identify active subdomains of the target host.
    Verifies both DNS resolution and HTTP/HTTPS responses to filter out dead hosts.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"SubdomainScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            if target.startswith(("http://", "https://")):
                domain = urlparse(target).hostname or ""
            else:
                domain = target.split("/")[0]

            parts = domain.split(".")
            active_subs = []
            
            if len(parts) >= 2:
                root_domain = ".".join(parts[-2:])
                subdomains = ["www", "mail", "dev", "api", "admin"]
                
                with SafeHTTPClient(timeout=1.5) as client:
                    for sub in subdomains:
                        sub_domain = f"{sub}.{root_domain}"
                        try:
                            # 1. Verify DNS resolution
                            ips = socket.gethostbyname(sub_domain)
                            
                            # 2. Verify HTTP/HTTPS response
                            is_active = False
                            for proto in ("http", "https"):
                                try:
                                    resp = client.head(f"{proto}://{sub_domain}")
                                    is_active = True
                                    break
                                except Exception:
                                    try:
                                        resp = client.get(f"{proto}://{sub_domain}")
                                        is_active = True
                                        break
                                    except Exception:
                                        pass
                            
                            if is_active:
                                active_subs.append(f"{sub_domain} ({ips})")
                        except Exception:
                            # Subdomain did not resolve or connection was refused, ignore
                            pass

                if active_subs:
                    findings.append({
                        "title": "Active Subdomains Discovered",
                        "severity": "Informational",
                        "confidence": "High",
                        "evidence": f"Active subdomains: {', '.join(active_subs)}",
                        "http_status": "N/A",
                        "affected_url": root_domain,
                        "scanner_name": "SubdomainScanner",
                        "detection_method": "DNS + HTTP Verification",
                        "timestamp": datetime_now_utc_str(),
                        "description": f"Identified active subdomains associated with root domain: {', '.join(active_subs)}.",
                        "recommendation": "Ensure all public subdomains undergo regular security audits and domain authorization reviews."
                    })
            
            if not findings:
                findings.append({
                    "title": "Subdomain Reconnaissance Clean",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Tested subdomains: www, mail, dev, api, admin. None resolved and responded to HTTP.",
                    "http_status": "N/A",
                    "affected_url": target,
                    "scanner_name": "SubdomainScanner",
                    "detection_method": "DNS + HTTP Verification",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Subdomain scanning completed. No active common subdomains responded to routing tests.",
                    "recommendation": "Perform full brute-force subdomain scans periodically."
                })
        except Exception as e:
            logger.error(f"SubdomainScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Subdomain Scan Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": target,
                "scanner_name": "SubdomainScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform subdomain mapping. Error: {str(e)}",
                "recommendation": "Verify target domain registration and status."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"SubdomainScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "SubdomainScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
