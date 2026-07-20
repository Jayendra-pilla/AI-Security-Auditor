from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from bs4 import BeautifulSoup
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

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
            
            html_content = resp.text
            soup = BeautifulSoup(html_content, "html.parser")
            forms = soup.find_all("form")

            # Check if there are any meta tags representing CSRF tokens (commonly used by Single Page Apps / AJAX frameworks)
            meta_csrf = False
            meta_tags = soup.find_all("meta")
            for meta in meta_tags:
                name = meta.get("name", "").lower()
                if "csrf" in name or "xsrf" in name:
                    meta_csrf = True
                    break

            # Check if the page has javascript indicating CSRF integration
            js_csrf = False
            scripts = soup.find_all("script")
            for script in scripts:
                script_text = script.string or ""
                if "csrf" in script_text.lower() or "xsrf" in script_text.lower():
                    js_csrf = True
                    break

            # Check SameSite cookie protection from response headers
            has_samesite_protection = False
            set_cookies = resp.headers.get_list("set-cookie")
            for cookie in set_cookies:
                cookie_lower = cookie.lower()
                if "samesite=strict" in cookie_lower or "samesite=lax" in cookie_lower:
                    has_samesite_protection = True

            # Differentiate SPA frameworks to prevent false positives (Phase 5 requirement)
            from app.scanners.scanner_utils import get_tech_fingerprint
            tech = get_tech_fingerprint(target)
            js_fw = tech.get("js_framework")
            is_spa = js_fw in ("React", "Angular", "Vue", "Nuxt") or "react" in html_content.lower() or "ng-version" in html_content.lower() or "data-reactroot" in html_content.lower()

            state_changing_forms = 0
            missing_csrf_forms = []

            if is_spa:
                # Skip HTML form checks for React/Angular/Vue
                findings.append({
                    "title": "SPA CSRF Verification (React/Vue/Angular Detected)",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"Framework: {js_fw or 'React/Vue/Angular (Meta/DOM matched)'}",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "CSRFScanner",
                    "detection_method": "Technology-Aware Verification",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Single Page Application (SPA) architecture detected. Static HTML forms do not require individual hidden tokens since state mutations are handled via API calls using headers.",
                    "recommendation": "Ensure REST APIs require secure CSRF tokens or token-based authorization (JWT) headers."
                })
                # Empty forms to bypass form loop
                forms = []

            for form in forms:
                method = form.get("method", "get").lower()
                if method in ("post", "put", "delete"):
                    state_changing_forms += 1
                    inputs = form.find_all("input")
                    has_csrf = False
                    
                    for inp in inputs:
                        name = inp.get("name", "").lower()
                        inp_type = inp.get("type", "").lower()
                        if any(tok in name for tok in ("csrf", "token", "xsrf", "authenticity")) or (inp_type == "hidden" and "csrf" in name):
                            has_csrf = True
                            break
                    
                    if not has_csrf:
                        form_id = form.get("id") or form.get("action") or "unnamed form"
                        missing_csrf_forms.append(form_id)

            if missing_csrf_forms:
                cvss = get_cvss("csrf_missing_token")
                mitre = get_mitre_mapping("csrf")
                
                if has_samesite_protection or meta_csrf or js_csrf:
                    conf = calculate_confidence(
                        validation_methods=["HTML Form Analysis", "Header Validation"],
                        evidence_quality="high",
                    )
                    findings.append({
                        "title": "Mitigated CSRF Configuration (SameSite or Client-Side Tokens Present)",
                        "severity": "Informational",
                        "confidence": conf["confidence"],
                        "evidence": f"POST forms: {missing_csrf_forms}. SameSite cookie: {has_samesite_protection}, Meta CSRF: {meta_csrf}, JS CSRF: {js_csrf}.",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "CSRFScanner",
                        "detection_method": "HTML Form and Cookie Inspection",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": "GET",
                        "response_headers": str(dict(resp.headers))[:200],
                        "response_snippet": str(missing_csrf_forms)[:200],
                        "matched_payload": "N/A",
                        "matched_header": "N/A",
                        "owasp_mapping": "A01:2021-Broken Access Control",
                        "cwe_mapping": "CWE-352",
                        # Informational finding, no CVSS vector as per Phase 7
                        "cvss_estimate": "0.0",
                        "references": ["https://owasp.org/www-community/attacks/Cross-Site_Request_Forgery_(CSRF)"],
                        "description": f"Some state-changing forms lack explicit hidden CSRF tokens: {missing_csrf_forms}. However, the application uses SameSite cookies or JS/meta tags, mitigating standard cross-site request forgery.",
                        "recommendation": "Maintain SameSite configuration and verify that API clients attach headers like X-CSRF-Token dynamically."
                    })
                else:
                    conf = calculate_confidence(
                        validation_methods=["HTML Form Analysis"],
                        evidence_quality="high",
                    )
                    findings.append({
                        "title": "Form Missing Anti-CSRF Token Protection",
                        "severity": "Medium",
                        "confidence": conf["confidence"],
                        "evidence": f"POST forms: {missing_csrf_forms} missing hidden tokens.",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "CSRFScanner",
                        "detection_method": "HTML Form Inspection",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": "GET",
                        "response_headers": str(dict(resp.headers))[:200],
                        "response_snippet": str(missing_csrf_forms)[:200],
                        "matched_payload": "N/A",
                        "matched_header": "N/A",
                        "owasp_mapping": "A01:2021-Broken Access Control",
                        "cwe_mapping": "CWE-352",
                        "cvss_estimate": str(cvss.get("base_score", "6.5")),
                        "cvss_vector": cvss.get("vector", ""),
                        "mitre_attack": mitre,
                        "references": ["https://owasp.org/www-community/attacks/Cross-Site_Request_Forgery_(CSRF)"],
                        "description": f"Detected state-changing HTML forms ({missing_csrf_forms}) that lack visible anti-CSRF token fields, and no alternative mitigations (SameSite cookies or meta tags) were detected.",
                        "recommendation": "Integrate secure anti-CSRF tokens (unique per session) in all POST/PUT/DELETE forms, and validate them on the server side."
                    })
                    severity = "Medium"
                    status = "warning"
            else:
                findings.append({
                    "title": "CSRF Protections Verified",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "All identified POST forms contain token fields, or no POST forms were found.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "CSRFScanner",
                    "detection_method": "HTML Form and Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "description": "All state-changing forms use anti-CSRF hidden parameters, or there are no state-changing forms.",
                    "recommendation": "Verify that backend CSRF validation is active for all state-changing endpoints."
                })

        except Exception as e:
            logger.error(f"CSRFScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "CSRF Scan Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": url,
                "scanner_name": "CSRFScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
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
