from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class ClickjackingScanner:
    """
    Scanner to check frame security headers preventing clickjacking exploits.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"ClickjackingScanner starting for target: {target}")
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

            x_frame = resp.headers.get("X-Frame-Options", "").lower()
            csp = resp.headers.get("Content-Security-Policy", "").lower()
            
            has_protection = False
            if "deny" in x_frame or "sameorigin" in x_frame:
                has_protection = True
            if "frame-ancestors" in csp:
                has_protection = True

            if not has_protection:
                findings.append({
                    "title": "Clickjacking Exposure",
                    "severity": "Medium",
                    "description": "The target page does not use X-Frame-Options or Content-Security-Policy: frame-ancestors to prevent framing.",
                    "recommendation": "Configure X-Frame-Options: SAMEORIGIN or CSP frame-ancestors directive."
                })
                severity = "Medium"
                status = "warning"
        except Exception as e:
            logger.error(f"ClickjackingScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Clickjacking Verification Failed",
                "severity": "Low",
                "description": f"Failed to test framing protections for {target}. Error: {str(e)}",
                "recommendation": "Configure anti-clickjacking headers and verify them manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"ClickjackingScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "ClickjackingScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
