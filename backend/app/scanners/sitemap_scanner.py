from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from app.scanners.scanner_utils import datetime_now_utc_str

logger = logging.getLogger(__name__)

class SitemapScanner:
    """
    Scanner to detect and validate sitemap.xml configuration files.
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
                content = resp.text
                
                # Check format validity
                is_valid_format = False
                if "<urlset" in content or "<sitemapindex" in content:
                    is_valid_format = True
                
                # Count URLs/Locations
                soup = BeautifulSoup(content, "xml")
                loc_tags = soup.find_all("loc")
                url_count = len(loc_tags)

                format_status = "Valid XML Sitemap Format" if is_valid_format else "Invalid/Malformed Sitemap Format"
                
                findings.append({
                    "title": "Sitemap Discovered",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"URL: {sitemap_url}, URLs found: {url_count}, Format: {format_status}",
                    "http_status": resp.status_code,
                    "affected_url": sitemap_url,
                    "scanner_name": "SitemapScanner",
                    "detection_method": "Sitemap XML Parsing",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(dict(resp.headers)),
                    "response_snippet": content[:200],
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "description": f"A sitemap file was discovered at {sitemap_url}. It contains {url_count} URL references and is formatted as: {format_status}.",
                    "recommendation": "Verify that sitemap.xml does not expose private, testing, staging, or unlinked admin/config URLs."
                })
            else:
                # Do NOT report missing sitemap as a vulnerability. It is purely Informational.
                findings.append({
                    "title": "Sitemap Not Found",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"HTTP status code {resp.status_code}",
                    "http_status": resp.status_code,
                    "affected_url": sitemap_url,
                    "scanner_name": "SitemapScanner",
                    "detection_method": "Sitemap Check",
                    "timestamp": datetime_now_utc_str(),
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
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": sitemap_url,
                "scanner_name": "SitemapScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform sitemap checks on {target}. Error: {str(e)}",
                "recommendation": "Ensure domain is reachable and verify sitemap accessibility manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"SitemapScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "SitemapScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
