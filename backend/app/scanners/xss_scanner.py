from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class XSSScanner:
    """
    Scanner to detect potential Reflected Cross-Site Scripting (XSS) exposures.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"XSSScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            xss_probe = "xss_safe_probe_12345"
            test_url = f"{url}?q={xss_probe}"
            
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(test_url, follow_redirects=True)
            
            if xss_probe in resp.text:
                findings.append({
                    "title": "Reflected Input Detected (Potential XSS)",
                    "severity": "High",
                    "description": "Input value passed to URL query parameter was reflected raw in the HTML response body.",
                    "recommendation": "Implement context-aware output encoding, escape user inputs, and enforce a strong Content Security Policy."
                })
                severity = "High"
                status = "warning"
            else:
                findings.append({
                    "title": "Reflected XSS Check Clean",
                    "severity": "Informational",
                    "description": "Tested URL query parameter reflection. No raw reflections detected.",
                    "recommendation": "Continue validating inputs and escaping outputs globally."
                })
        except Exception as e:
            logger.error(f"XSSScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "XSS Probe Failed",
                "severity": "Low",
                "description": f"Could not perform reflected XSS checks. Error: {str(e)}",
                "recommendation": "Audit application controllers and views manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"XSSScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "XSSScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
