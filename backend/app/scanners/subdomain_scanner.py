import socket
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SubdomainScanner:
    """
    Scanner to identify common subdomains of the target host.
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
            if len(parts) >= 2:
                root_domain = ".".join(parts[-2:])
                subdomains = ["www", "mail", "dev", "api", "admin"]
                found_subs = []
                
                for sub in subdomains:
                    sub_domain = f"{sub}.{root_domain}"
                    try:
                        socket.gethostbyname(sub_domain)
                        found_subs.append(sub_domain)
                    except Exception:
                        pass
                
                if found_subs:
                    findings.append({
                        "title": "Subdomains Discovered",
                        "severity": "Informational",
                        "description": f"Identified active subdomains associated with root domain: {', '.join(found_subs)}.",
                        "recommendation": "Ensure all public subdomains undergo regular security audits."
                    })
            
            if not findings:
                findings.append({
                    "title": "Subdomain Reconnaissance Clean",
                    "severity": "Informational",
                    "description": "Subdomain scanning completed. No common subdomains resolved.",
                    "recommendation": "Perform full brute-force subdomain scans periodically."
                })
        except Exception as e:
            logger.error(f"SubdomainScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Subdomain Scan Failed",
                "severity": "Low",
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
