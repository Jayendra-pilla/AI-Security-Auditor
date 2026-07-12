from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class OpenRedirectScanner:
    """
    Scanner to inspect query parameters for open redirection weaknesses.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"OpenRedirectScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            test_params = ["redirect", "url", "next", "return", "destination"]
            exploit_target = "https://google.com"
            has_vulnerability = False
            
            with SafeHTTPClient(timeout=2.0) as client:
                for param in test_params:
                    test_url = f"{base_url}?{param}={exploit_target}"
                    try:
                        resp = client.get(test_url, follow_redirects=False)
                        if resp.status_code in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if location.startswith(exploit_target) or exploit_target in location:
                                findings.append({
                                    "title": "Open Redirect Vulnerability",
                                    "severity": "High",
                                    "description": f"Target parameter '{param}' redirects to external domains without verification.",
                                    "recommendation": "Restrict redirects to relative URLs or apply whitelists of trusted domains."
                                })
                                severity = "High"
                                status = "warning"
                                has_vulnerability = True
                                break
                    except Exception:
                        pass
            
            if not has_vulnerability:
                findings.append({
                    "title": "Open Redirect Check Clean",
                    "severity": "Informational",
                    "description": "Tested common redirection parameters. No open redirects detected.",
                    "recommendation": "Enforce strict redirect path validations in site controller code."
                })
        except Exception as e:
            logger.error(f"OpenRedirectScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Open Redirect Verification Failed",
                "severity": "Low",
                "description": f"Failed to test redirects on {target}. Error: {str(e)}",
                "recommendation": "Manually audit redirect controllers."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"OpenRedirectScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "OpenRedirectScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
