from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class HeaderScanner:
    """
    Scanner to inspect HTTP security headers of the target.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"HeaderScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            with SafeHTTPClient(timeout=2.0) as client:
                try:
                    resp = client.head(url, follow_redirects=True)
                except Exception:
                    resp = client.get(url, follow_redirects=True)
                
                headers = resp.headers
                
                if "Content-Security-Policy" not in headers:
                    findings.append({
                        "title": "Missing CSP Header",
                        "severity": "Medium",
                        "description": "Content Security Policy (CSP) header is not configured on the target.",
                        "recommendation": "Implement a strong Content-Security-Policy header."
                    })
                    severity = "Medium"
                    status = "warning"
                if "Strict-Transport-Security" not in headers:
                    findings.append({
                        "title": "Missing HSTS Header",
                        "severity": "Low",
                        "description": "HTTP Strict Transport Security (HSTS) header is missing.",
                        "recommendation": "Configure the Strict-Transport-Security header."
                    })
                    if severity == "Informational":
                        severity = "Low"
                        status = "warning"
                if "X-Frame-Options" not in headers:
                    findings.append({
                        "title": "Missing X-Frame-Options Header",
                        "severity": "Medium",
                        "description": "X-Frame-Options header is missing, exposing the site to clickjacking.",
                        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN."
                    })
                    severity = "Medium"
                    status = "warning"
        except Exception as e:
            logger.error(f"HeaderScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Header Inspection Failed",
                "severity": "Low",
                "description": f"Could not perform real-time header scan on {target}. Error: {str(e)}",
                "recommendation": "Verify target accessibility and check HTTP headers manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"HeaderScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "HeaderScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
