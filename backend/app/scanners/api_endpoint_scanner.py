from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class APIEndpointScanner:
    """
    Scanner to detect open API paths and public routing documentations.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"APIEndpointScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            endpoints = ["/api", "/api/v1", "/swagger", "/docs", "/openapi.json"]
            exposed = []
            
            with SafeHTTPClient(timeout=2.0) as client:
                for ep in endpoints:
                    ep_url = urljoin(base_url.rstrip("/") + "/", ep.lstrip("/"))
                    try:
                        resp = client.get(ep_url, follow_redirects=True)
                        if resp.status_code == 200:
                            exposed.append(ep)
                    except Exception:
                        pass
            
            if exposed:
                findings.append({
                    "title": "Publicly Accessible API Endpoints",
                    "severity": "Medium",
                    "description": f"Common public API or documentation endpoints were resolved on the server: {', '.join(exposed)}.",
                    "recommendation": "Verify that these endpoints require authorization or are intentionally exposed. Limit documentation access to internal networks if possible."
                })
                severity = "Medium"
                status = "warning"
            else:
                findings.append({
                    "title": "API Endpoint Scans Clean",
                    "severity": "Informational",
                    "description": "Tested common API and swagger endpoint paths. No open resources resolved.",
                    "recommendation": "Implement strict route validation and rate limiting on all endpoints."
                })
        except Exception as e:
            logger.error(f"APIEndpointScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "API Probing Failure",
                "severity": "Low",
                "description": f"Failed to test api directories on target. Error: {str(e)}",
                "recommendation": "Manually inspect active endpoints and trace server routes."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"APIEndpointScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "APIEndpointScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
