from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class ClickjackingScanner:
    """
    Scanner to check frame security headers preventing clickjacking exploits.
    Only analyzes HTML pages, ignoring images, JSON APIs, and downloads.
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

            content_type = resp.headers.get("Content-Type", "").lower()
            is_html = "text/html" in content_type

            if not is_html:
                findings.append({
                    "title": "Clickjacking Scan Skipped (Non-HTML Content)",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"Content-Type: '{content_type}'",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "ClickjackingScanner",
                    "detection_method": "Content-Type Validation",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Target response is not an HTML document. Clickjacking frame protections are not required/applicable.",
                    "recommendation": "Maintain standard header security policies across all application routes."
                })
            else:
                x_frame = resp.headers.get("X-Frame-Options", "").lower()
                csp = resp.headers.get("Content-Security-Policy", "").lower()
                
                has_protection = False
                if "deny" in x_frame or "sameorigin" in x_frame:
                    has_protection = True
                if "frame-ancestors" in csp:
                    has_protection = True

                if not has_protection:
                    cvss = get_cvss("missing_x_frame_options")
                    conf = calculate_confidence(
                        validation_methods=["Header Validation"],
                        evidence_quality="high",
                    )
                    findings.append({
                        "title": "Clickjacking Exposure",
                        "severity": "Medium",
                        "confidence": conf["confidence"],
                        "evidence": f"X-Frame-Options: '{x_frame}', CSP: '{csp}'",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "ClickjackingScanner",
                        "detection_method": "Response Header Inspection",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(resp.headers))[:200],
                        "matched_payload": "N/A",
                        "matched_header": "X-Frame-Options / Content-Security-Policy",
                        "owasp_mapping": "A05:2021-Security Misconfiguration",
                        "cwe_mapping": "CWE-1021",
                        "cvss_estimate": str(cvss.get("base_score", "6.1")),
                        "cvss_vector": cvss.get("vector", ""),
                        "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
                        "description": "The target page does not use X-Frame-Options or Content-Security-Policy: frame-ancestors to prevent framing, leaving it vulnerable to Clickjacking attacks.",
                        "recommendation": "Configure X-Frame-Options: SAMEORIGIN or CSP frame-ancestors directive."
                    })
                    severity = "Medium"
                    status = "warning"
                else:
                    findings.append({
                        "title": "Clickjacking Protection Verified",
                        "severity": "Informational",
                        "confidence": "High",
                        "evidence": f"X-Frame-Options: '{x_frame}', CSP frame-ancestors present: {'frame-ancestors' in csp}",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "ClickjackingScanner",
                        "detection_method": "Response Header Inspection",
                        "timestamp": datetime_now_utc_str(),
                        "description": "The page uses X-Frame-Options or Content-Security-Policy frame-ancestors to prohibit framing.",
                        "recommendation": "No action required."
                    })
        except Exception as e:
            logger.error(f"ClickjackingScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Clickjacking Verification Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": url,
                "scanner_name": "ClickjackingScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
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
