import socket
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DNSScanner:
    """
    Scanner to resolve target domain names and retrieve system DNS configurations.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"DNSScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            if target.startswith(("http://", "https://")):
                host = urlparse(target).hostname or ""
            else:
                host = target.split("/")[0]

            if not host:
                host = target

            addr_info = socket.getaddrinfo(host, None)
            ips = sorted(list(set(info[4][0] for info in addr_info)))
            
            findings.append({
                "title": "DNS Host Resolution",
                "severity": "Informational",
                "description": f"Host '{host}' successfully resolved to: {', '.join(ips)}.",
                "recommendation": "Maintain strict DNS administration policies and enable DNSSEC."
            })
        except Exception as e:
            logger.error(f"DNSScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "DNS Host Resolution Failure",
                "severity": "Low",
                "description": f"Target host '{target}' could not be resolved. Error: {str(e)}",
                "recommendation": "Verify that domain is registered and check DNS server configurations."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"DNSScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "DNSScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
