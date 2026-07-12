from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class CookieScanner:
    """
    Scanner to analyze HTTP cookie flags for missing Secure or HttpOnly configurations.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"CookieScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(url, follow_redirects=True)
                
            set_cookie_headers = resp.headers.get_list("set-cookie")
            for sc in set_cookie_headers:
                sc_lower = sc.lower()
                if "secure" not in sc_lower:
                    findings.append({
                        "title": "Insecure Cookie Flag",
                        "severity": "Medium",
                        "description": f"Cookie in header '{sc}' is missing the Secure attribute.",
                        "recommendation": "Set the Secure attribute on all sensitive cookies."
                    })
                    severity = "Medium"
                    status = "warning"
                if "httponly" not in sc_lower:
                    findings.append({
                        "title": "Missing HttpOnly Cookie Attribute",
                        "severity": "Medium",
                        "description": f"Cookie in header '{sc}' is missing the HttpOnly attribute.",
                        "recommendation": "Add HttpOnly attribute to prevent script-based cookie access."
                    })
                    severity = "Medium"
                    status = "warning"
        except Exception as e:
            logger.error(f"CookieScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Cookie Analysis Failed",
                "severity": "Low",
                "description": f"Failed to retrieve cookie configuration from target. Error: {str(e)}",
                "recommendation": "Manually inspect cookie attributes in a browser."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"CookieScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "CookieScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
