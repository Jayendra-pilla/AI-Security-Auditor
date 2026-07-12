from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class RobotsScanner:
    """
    Scanner to detect and inspect robots.txt configurations for sensitive path exposures.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"RobotsScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
            
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(robots_url, follow_redirects=True)
            
            if resp.status_code == 200:
                content = resp.text
                sensitive_keywords = ["admin", "login", "private", "backup", "secret", "wp-admin", "config", "conf", "db"]
                found_sensitive = []
                for line in content.splitlines():
                    line_strip = line.strip()
                    if line_strip.lower().startswith("disallow"):
                        parts = line_strip.split(":", 1)
                        if len(parts) > 1:
                            path = parts[1].strip()
                            for kw in sensitive_keywords:
                                if kw in path.lower():
                                    found_sensitive.append(path)
                                    break
                
                if found_sensitive:
                    findings.append({
                        "title": "Sensitive Path Exposure in robots.txt",
                        "severity": "Low",
                        "description": f"Robots.txt exposes sensitive paths to crawlers: {', '.join(found_sensitive[:5])}.",
                        "recommendation": "Do not list private folders/files in robots.txt. Enforce authorization controls on those folders instead."
                    })
                    severity = "Low"
                    status = "warning"
                else:
                    findings.append({
                        "title": "Robots.txt Discovered",
                        "severity": "Informational",
                        "description": "Robots.txt is present and does not disclose common sensitive pathways.",
                        "recommendation": "Ensure no internal or custom configuration directories are disclosed in robots.txt."
                    })
            else:
                findings.append({
                    "title": "Robots.txt Not Found",
                    "severity": "Informational",
                    "description": f"Robots.txt could not be retrieved from {robots_url} (HTTP {resp.status_code}).",
                    "recommendation": "Deploy a robots.txt file to guide search engine crawlers if required."
                })
        except Exception as e:
            logger.error(f"RobotsScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Robots.txt Scan Failed",
                "severity": "Low",
                "description": f"Could not scan robots.txt on {target}. Error: {str(e)}",
                "recommendation": "Verify target accessibility and inspect robots.txt manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"RobotsScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "RobotsScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
