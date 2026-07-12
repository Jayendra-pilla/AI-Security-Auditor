from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class SSLScanner:
    """
    Scanner to inspect TLS/SSL encryption configuration.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"SSLScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            if not target.startswith("https://") and target.startswith("http://"):
                findings.append({
                    "title": "Insecure HTTP Protocol",
                    "severity": "High",
                    "description": "The target website is accessible over unencrypted HTTP protocol.",
                    "recommendation": "Redirect all HTTP traffic to HTTPS and use TLS 1.3."
                })
                severity = "High"
                status = "warning"
            else:
                url = target if target.startswith("https://") else f"https://{target}"
                with SafeHTTPClient(timeout=2.0) as client:
                    client.head(url)
        except Exception as e:
            logger.error(f"SSLScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "SSL Connection Failed",
                "severity": "Low",
                "description": f"Could not verify SSL/TLS configuration for {target}. Error: {str(e)}",
                "recommendation": "Ensure domain has a valid SSL certificate installed."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"SSLScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "SSLScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
