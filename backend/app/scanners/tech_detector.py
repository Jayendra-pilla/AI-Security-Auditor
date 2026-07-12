from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

logger = logging.getLogger(__name__)

class TechDetector:
    """
    Scanner to identify technologies and backend framework disclosures via HTTP response headers.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"TechDetector starting for target: {target}")
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
            disclosures = []

            server = headers.get("Server")
            if server:
                disclosures.append(f"Server header: {server}")
            
            powered_by = headers.get("X-Powered-By")
            if powered_by:
                disclosures.append(f"X-Powered-By header: {powered_by}")

            asp_version = headers.get("X-AspNet-Version")
            if asp_version:
                disclosures.append(f"X-AspNet-Version header: {asp_version}")

            generator = headers.get("X-Generator")
            if generator:
                disclosures.append(f"X-Generator header: {generator}")

            if disclosures:
                findings.append({
                    "title": "Technology Disclosure",
                    "severity": "Low",
                    "description": f"The target discloses backend technologies or server details in HTTP headers: {', '.join(disclosures)}.",
                    "recommendation": "Configure the web server to disable signature headers (Server, X-Powered-By, X-AspNet-Version) or strip version details."
                })
                severity = "Low"
                status = "warning"
            else:
                findings.append({
                    "title": "Technology Disclosures Clean",
                    "severity": "Informational",
                    "description": "No technology disclosures detected in response headers.",
                    "recommendation": "Continue following configuration hardening practices."
                })
        except Exception as e:
            logger.error(f"TechDetector error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Technology Signature Probe Failed",
                "severity": "Low",
                "description": f"Could not perform technology detection on {target}. Error: {str(e)}",
                "recommendation": "Inspect HTTP headers manually using command-line tools like curl."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"TechDetector finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "TechDetector",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
