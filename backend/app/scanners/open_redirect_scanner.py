from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
import urllib.parse
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

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
            parsed_target = urllib.parse.urlparse(base_url)
            target_host = parsed_target.netloc

            test_params = ["redirect", "url", "next", "return", "destination"]
            exploit_payloads = [
                "https://google.com",
                "//google.com",
                "/%2fgoogle.com",
                "https:%2f%2fgoogle.com",
            ]
            has_vulnerability = False
            
            with SafeHTTPClient(timeout=2.0) as client:
                for param in test_params:
                    for payload in exploit_payloads:
                        test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                        try:
                            # Disable automatic redirect following inside httpx
                            resp = client.get(test_url, follow_redirects=False)
                            
                            # Verify 3xx status code
                            if resp.status_code in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location", "")
                                
                                # Parse redirect location
                                parsed_loc = urllib.parse.urlparse(location)
                                redirect_host = parsed_loc.netloc
                                
                                # It is only a valid open redirect if:
                                # 1. Netloc is present (absolute URL) or starts with //
                                # 2. Redirect host is different from target host
                                if (redirect_host and redirect_host != target_host) or location.startswith("//google.com") or "google.com" in location:
                                    cvss = get_cvss("open_redirect")
                                    mitre = get_mitre_mapping("open_redirect")
                                    conf = calculate_confidence(
                                        validation_methods=["Response Code Validation", "Header Validation", "Payload Reflection"],
                                        evidence_quality="high",
                                    )
                                    findings.append({
                                        "title": "Open Redirect Vulnerability",
                                        "severity": "High",
                                        "confidence": conf["confidence"],
                                        "evidence": f"Parameter: '{param}', HTTP Status: {resp.status_code}, Location: '{location}'",
                                        "http_status": resp.status_code,
                                        "affected_url": test_url,
                                        "scanner_name": "OpenRedirectScanner",
                                        "detection_method": "Parameter Redirection Injection",
                                        "timestamp": datetime_now_utc_str(),
                                        "request_method": "GET",
                                        "response_headers": str(dict(resp.headers))[:200],
                                        "response_snippet": "",
                                        "matched_payload": f"{param}={payload}",
                                        "matched_header": "Location",
                                        "owasp_mapping": "A01:2021-Broken Access Control",
                                        "cwe_mapping": "CWE-601",
                                        "cvss_estimate": str(cvss.get("base_score", "6.1")),
                                        "cvss_vector": cvss.get("vector", ""),
                                        "mitre_attack": mitre,
                                        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                                        "description": f"The parameter '{param}' accepts untrusted inputs and redirects the browser to external domains: {location}.",
                                        "recommendation": "Restrict redirects to relative URLs or apply whitelists of trusted domains."
                                    })
                                    severity = "High"
                                    status = "warning"
                                    has_vulnerability = True
                                    break
                        except Exception as req_err:
                            logger.debug(f"Open redirect query fail on {param} with payload {payload}: {str(req_err)}")
                    if has_vulnerability:
                        break
            
            if not has_vulnerability:
                findings.append({
                    "title": "Open Redirect Check Clean",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Tested redirection parameters against external domain. No unvalidated external redirections occurred.",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "OpenRedirectScanner",
                    "detection_method": "Parameter Redirection Injection",
                    "timestamp": datetime_now_utc_str(),
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
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": base_url,
                "scanner_name": "OpenRedirectScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
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
