from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class SitemapScanner:
    """
    Scanner to detect and validate access to sitemap.xml files.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"SitemapScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            sitemap_url = urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
            
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(sitemap_url, follow_redirects=True)
            
            if resp.status_code == 200:
                findings.append({
                    "title": "Sitemap Discovered",
                    "severity": "Informational",
                    "description": "Sitemap XML is publicly accessible.",
                    "recommendation": "Verify that sitemap.xml does not expose private, test, staging, or unlinked URLs."
                })
            else:
                findings.append({
                    "title": "Sitemap Not Found",
                    "severity": "Informational",
                    "description": f"Sitemap XML could not be retrieved from {sitemap_url} (HTTP {resp.status_code}).",
                    "recommendation": "Publish a sitemap.xml to guide search engine crawlers if required."
                })
        except Exception as e:
            logger.error(f"SitemapScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Sitemap Scan Failed",
                "severity": "Low",
                "description": f"Could not perform sitemap checks on {target}. Error: {str(e)}",
                "recommendation": "Ensure domain is reachable and verify sitemap accessibility manually."
            })

           # Correct formatting matching the expected results structure
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"SitemapScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "SitemapScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
