from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class CSRFScanner:
    """
    Scanner to detect HTML forms missing anti-CSRF protection tokens.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"CSRFScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(url, follow_redirects=True)
            
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            missing_csrf_count = 0
            
            for form in forms:
                method = form.get("method", "get").lower()
                if method == "post":
                    inputs = form.find_all("input")
                    has_csrf = False
                    for inp in inputs:
                        name = inp.get("name", "").lower()
                        if "csrf" in name or "token" in name:
                            has_csrf = True
                            break
                    if not has_csrf:
                        missing_csrf_count += 1
            
            if missing_csrf_count > 0:
                findings.append({
                    "title": "Potential CSRF Vulnerability",
                    "severity": "High",
                    "description": f"Detected {missing_csrf_count} POST form(s) lacking visible anti-CSRF token fields.",
                    "recommendation": "Integrate anti-CSRF tokens in all state-changing HTML forms."
                })
                severity = "High"
                status = "warning"
            else:
                findings.append({
                    "title": "CSRF Form Protections Inspected",
                    "severity": "Informational",
                    "description": "All identified POST forms contain token fields, or no POST forms were found.",
                    "recommendation": "Verify that backend CSRF validation is active for all state-changing endpoints."
                })
        except Exception as e:
            logger.error(f"CSRFScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "CSRF Scan Failed",
                "severity": "Low",
                "description": f"Failed to parse forms on {target}. Error: {str(e)}",
                "recommendation": "Inspect HTML forms manually to check for anti-CSRF measures."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"CSRFScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "CSRFScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
