from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class CookieScanner:
    """
    Scanner to analyze HTTP cookie flags for missing Secure, HttpOnly, SameSite, or other weak configurations.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"CookieScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(url, follow_redirects=True)
                
            set_cookie_headers = resp.headers.get_list("set-cookie")
            
            # Detect duplicate cookies in headers
            cookie_names = []
            for sc in set_cookie_headers:
                parts = sc.split(";", 1)[0].split("=", 1)
                if parts:
                    cookie_names.append(parts[0].strip())
            
            duplicates = set([n for n in cookie_names if cookie_names.count(n) > 1])
            if duplicates:
                conf = calculate_confidence(
                    validation_methods=["Header Validation"],
                    evidence_quality="high"
                )
                findings.append({
                    "title": "Duplicate Cookie Definitions",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": f"Duplicate cookie names: {list(duplicates)}",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "CookieScanner",
                    "detection_method": "Response Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(resp.headers))[:200],
                    "response_snippet": str(set_cookie_headers)[:200],
                    "matched_payload": "N/A",
                    "matched_header": "Set-Cookie",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-16",
                    "cvss_estimate": "3.1",
                    "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    "description": f"The application sent duplicate cookie declarations for: {list(duplicates)}. This can cause collision or data overrides in browsers.",
                    "recommendation": "Ensure cookie state is managed cleanly and each unique cookie is defined once per response."
                })
                severity = "Low"
                status = "warning"

            # Parse each Set-Cookie header
            for sc in set_cookie_headers:
                sc_lower = sc.lower()
                
                cookie_first_part = sc.split(";", 1)[0]
                cookie_name = cookie_first_part.split("=", 1)[0].strip()

                # Differentiate and ignore analytics/tracking cookies to prevent false positives
                analytics_indicators = ("_ga", "_gid", "_gat", "_utm", "amplitude", "mixpanel", "_hj", "optimizely", "_cl", "_gaexp", "doubleclick")
                if any(indicator in cookie_name.lower() for indicator in analytics_indicators):
                    logger.debug(f"CookieScanner: Ignoring analytics/tracking cookie '{cookie_name}' to prevent false positives.")
                    continue

                # Check Secure
                if "secure" not in sc_lower:
                    cvss = get_cvss("insecure_cookie")
                    mitre = get_mitre_mapping("insecure_cookie")
                    conf = calculate_confidence(
                        validation_methods=["Cookie Inspection"],
                        evidence_quality="high"
                    )
                    findings.append({
                        "title": "Insecure Cookie Flag",
                        "severity": "Medium",
                        "confidence": conf["confidence"],
                        "evidence": f"Cookie: '{cookie_name}' in Header: '{sc}'",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "CookieScanner",
                        "detection_method": "Cookie Flag Validation",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(resp.headers))[:200],
                        "response_snippet": sc[:200],
                        "matched_payload": "N/A",
                        "matched_header": "Set-Cookie",
                        "owasp_mapping": "A05:2021-Security Misconfiguration",
                        "cwe_mapping": "CWE-614",
                        "cvss_estimate": str(cvss.get("base_score", "5.3")),
                        "cvss_vector": cvss.get("vector", ""),
                        "mitre_attack": mitre,
                        "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                        "description": f"The cookie '{cookie_name}' is missing the Secure attribute, allowing transmission over unencrypted HTTP.",
                        "recommendation": "Set the Secure attribute on all application cookies."
                    })
                    severity = "Medium"
                    status = "warning"

                # Check HttpOnly
                if "httponly" not in sc_lower:
                    cvss = get_cvss("insecure_cookie")
                    mitre = get_mitre_mapping("insecure_cookie")
                    conf = calculate_confidence(
                        validation_methods=["Cookie Inspection"],
                        evidence_quality="high"
                    )
                    findings.append({
                        "title": "Missing HttpOnly Cookie Attribute",
                        "severity": "Medium",
                        "confidence": conf["confidence"],
                        "evidence": f"Cookie: '{cookie_name}' in Header: '{sc}'",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "CookieScanner",
                        "detection_method": "Cookie Flag Validation",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(resp.headers))[:200],
                        "response_snippet": sc[:200],
                        "matched_payload": "N/A",
                        "matched_header": "Set-Cookie",
                        "owasp_mapping": "A05:2021-Security Misconfiguration",
                        "cwe_mapping": "CWE-1004",
                        "cvss_estimate": str(cvss.get("base_score", "5.3")),
                        "cvss_vector": cvss.get("vector", ""),
                        "mitre_attack": mitre,
                        "references": ["https://owasp.org/www-community/HttpOnly"],
                        "description": f"The cookie '{cookie_name}' is missing the HttpOnly attribute, exposing it to client-side XSS scripting theft.",
                        "recommendation": "Add the HttpOnly attribute to all sensitive session or authorization cookies."
                    })
                    severity = "Medium"
                    status = "warning"

                # Check SameSite
                if "samesite" not in sc_lower:
                    cvss = get_cvss("insecure_cookie")
                    mitre = get_mitre_mapping("insecure_cookie")
                    conf = calculate_confidence(
                        validation_methods=["Cookie Inspection"],
                        evidence_quality="high"
                    )
                    findings.append({
                        "title": "Missing SameSite Cookie Attribute",
                        "severity": "Low",
                        "confidence": conf["confidence"],
                        "evidence": f"Cookie: '{cookie_name}' in Header: '{sc}'",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "CookieScanner",
                        "detection_method": "Cookie Flag Validation",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(resp.headers))[:200],
                        "response_snippet": sc[:200],
                        "matched_payload": "N/A",
                        "matched_header": "Set-Cookie",
                        "owasp_mapping": "A01:2021-Broken Access Control",
                        "cwe_mapping": "CWE-1275",
                        "cvss_estimate": str(cvss.get("base_score", "3.1")),
                        "cvss_vector": cvss.get("vector", ""),
                        "mitre_attack": mitre,
                        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                        "description": f"The cookie '{cookie_name}' is missing the SameSite attribute, which defaults it to lax/none and increases CSRF risks.",
                        "recommendation": "Configure SameSite=Lax or SameSite=Strict on cookies."
                    })
                    if severity == "Informational":
                        severity = "Low"
                        status = "warning"
                else:
                    if "samesite=none" in sc_lower and "secure" not in sc_lower:
                        cvss = get_cvss("insecure_cookie")
                        mitre = get_mitre_mapping("insecure_cookie")
                        conf = calculate_confidence(
                            validation_methods=["Cookie Inspection"],
                            evidence_quality="high"
                        )
                        findings.append({
                            "title": "Invalid SameSite=None Cookie Configuration",
                            "severity": "Medium",
                            "confidence": conf["confidence"],
                            "evidence": f"SameSite=None but Secure missing in cookie: '{cookie_name}'",
                            "http_status": resp.status_code,
                            "affected_url": str(resp.url),
                            "scanner_name": "CookieScanner",
                            "detection_method": "Cookie Flag Validation",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": resp.request.method,
                            "response_headers": str(dict(resp.headers))[:200],
                            "response_snippet": sc[:200],
                            "matched_payload": "N/A",
                            "matched_header": "Set-Cookie",
                            "owasp_mapping": "A05:2021-Security Misconfiguration",
                            "cwe_mapping": "CWE-614",
                            "cvss_estimate": str(cvss.get("base_score", "4.8")),
                            "cvss_vector": cvss.get("vector", ""),
                            "mitre_attack": mitre,
                            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none"],
                            "description": f"SameSite=None is set but the Secure attribute is missing for cookie '{cookie_name}'. Browsers will reject this cookie.",
                            "recommendation": "Append the Secure attribute to all cookies configured with SameSite=None."
                        })
                        severity = "Medium"
                        status = "warning"

                # Check for weak session names missing security flags
                weak_names = ("session", "sid", "sess", "phpsessid", "jsessionid", "aspsessionid", "token", "auth", "jwt", "id")
                if any(w in cookie_name.lower() for w in weak_names) and ("httponly" not in sc_lower or "secure" not in sc_lower):
                    cvss = get_cvss("insecure_cookie")
                    mitre = get_mitre_mapping("insecure_cookie")
                    conf = calculate_confidence(
                        validation_methods=["Cookie Inspection"],
                        evidence_quality="high"
                    )
                    findings.append({
                        "title": f"Weak Security Configuration for Session Cookie: {cookie_name}",
                        "severity": "Medium",
                        "confidence": conf["confidence"],
                        "evidence": f"Session cookie '{cookie_name}' lacks Secure or HttpOnly flags.",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "CookieScanner",
                        "detection_method": "Session Cookie Discovery",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(resp.headers))[:200],
                        "response_snippet": sc[:200],
                        "matched_payload": "N/A",
                        "matched_header": "Set-Cookie",
                        "owasp_mapping": "A01:2021-Broken Access Control",
                        "cwe_mapping": "CWE-1004",
                        "cvss_estimate": str(cvss.get("base_score", "5.9")),
                        "cvss_vector": cvss.get("vector", ""),
                        "mitre_attack": mitre,
                        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                        "description": f"The session/authorization cookie '{cookie_name}' is not securely protected with HttpOnly and Secure flags, making it vulnerable to session hijacking.",
                        "recommendation": "Configure all session management and auth tokens with strict Secure, HttpOnly, and SameSite=Lax flags."
                    })
                    severity = "Medium"
                    status = "warning"

                # Check for excessively long cookie lifetime (Max-Age > 1 year / 31536000s)
                import re
                max_age_match = re.search(r'max-age\s*=\s*(\d+)', sc_lower)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 31536000:
                        conf = calculate_confidence(
                            validation_methods=["Cookie Inspection"],
                            evidence_quality="high"
                        )
                        findings.append({
                            "title": "Persistent Cookie Expiry Policy",
                            "severity": "Informational",
                            "confidence": conf["confidence"],
                            "evidence": f"Cookie '{cookie_name}' max-age is set to: {max_age} seconds",
                            "http_status": resp.status_code,
                            "affected_url": str(resp.url),
                            "scanner_name": "CookieScanner",
                            "detection_method": "Cookie Expiration Parsing",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": resp.request.method,
                            "response_snippet": sc[:200],
                            # No CVSS generated for Informational findings as per Phase 7
                            "description": f"The cookie '{cookie_name}' has an excessively long lifespan ({max_age} seconds), exposing cookie values on shared systems.",
                            "recommendation": "Limit session and application cookie lifespans to standard durations (e.g. max-age of a few hours or days)."
                        })

            if not findings:
                findings.append({
                    "title": "Cookies Verified Secure",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "No set-cookie headers present, or all returned cookies are configured with HttpOnly, Secure, and SameSite.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "CookieScanner",
                    "detection_method": "Response Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Cookie validation complete. All returned application cookies use hardened flags.",
                    "recommendation": "Continue validating cookie configurations during deployments."
                })

        except Exception as e:
            logger.error(f"CookieScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Cookie Analysis Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": url,
                "scanner_name": "CookieScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Failed to retrieve cookie configuration from target. Error: {str(e)}",
                "recommendation": "Manually inspect cookie attributes in a browser."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"CookieScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "CookieScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
