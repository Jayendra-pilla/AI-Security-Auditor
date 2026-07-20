from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from app.scanners.scanner_utils import get_tech_fingerprint, datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import confidence_for_header_finding, calculate_confidence

logger = logging.getLogger(__name__)

class HeaderScanner:
    """
    Scanner to inspect HTTP security headers of the target.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"HeaderScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            with SafeHTTPClient(timeout=3.0) as client:
                try:
                    resp = client.head(url, follow_redirects=True)
                except Exception:
                    resp = client.get(url, follow_redirects=True)
                
            headers = resp.headers
            content_type = headers.get("Content-Type", "").lower()
            is_json = "application/json" in content_type
            is_html = "text/html" in content_type

            # Check for duplicate headers
            header_keys = [k.lower() for k, _ in headers.items()]
            duplicates = set([k for k in header_keys if header_keys.count(k) > 1])
            if duplicates:
                conf = confidence_for_header_finding(True)
                findings.append({
                    "title": "Duplicate HTTP Response Headers",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": f"Duplicate headers: {', '.join(duplicates)}",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": str(resp.content[:100]),
                    "matched_payload": "N/A",
                    "matched_header": str(list(duplicates)),
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-16",
                    "cvss_estimate": "3.5",
                    "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    "description": f"The web server returned duplicate HTTP headers: {', '.join(duplicates)}. This can cause ambiguity in browser parsing.",
                    "recommendation": "Configure the web server to ensure each HTTP header is sent exactly once."
                })
                severity = "Low"
                status = "warning"

            # 1. CSP Inspection (Ignore if JSON API)
            if not is_json:
                csp = headers.get("Content-Security-Policy")
                if not csp:
                    vuln_sev = "Medium" if is_html else "Informational"
                    vuln_status = "warning" if is_html else "success"
                    conf = confidence_for_header_finding(False)
                    cvss = get_cvss("missing_csp")
                    mitre = get_mitre_mapping("xss")  # CSP maps to XSS prevention
                    
                    finding = {
                        "title": "Missing Content-Security-Policy Header",
                        "severity": vuln_sev,
                        "confidence": conf["confidence"],
                        "evidence": "No Content-Security-Policy header found.",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "HeaderScanner",
                        "detection_method": "Header Inspection",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(headers))[:200],
                        "response_snippet": "",
                        "matched_payload": "N/A",
                        "matched_header": "N/A",
                        "owasp_mapping": "A05:2021-Security Misconfiguration",
                        "cwe_mapping": "CWE-1021",
                        "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                        "description": "Content-Security-Policy (CSP) is missing. CSP helps mitigate XSS and clickjacking attacks.",
                        "recommendation": "Implement a robust CSP header containing strict script-src and frame-ancestors policies."
                    }
                    if is_html:
                        finding["cvss_estimate"] = str(cvss.get("base_score", "6.1"))
                        finding["cvss_vector"] = cvss.get("vector", "")
                        finding["mitre_attack"] = mitre
                    else:
                        finding["cvss_estimate"] = "0.0"

                    findings.append(finding)
                    if severity == "Informational" and vuln_sev != "Informational":
                        severity = vuln_sev
                        status = vuln_status
                else:
                    csp_lower = csp.lower()
                    
                    # Check for modern CSP security mitigations (Phase 4 requirement)
                    has_nonce = "nonce-" in csp_lower
                    has_strict_dynamic = "strict-dynamic" in csp_lower
                    has_hashes = any(h in csp_lower for h in ("sha256-", "sha384-", "sha512-"))
                    has_trusted_types = "require-trusted-types-for" in csp_lower
                    
                    weaknesses = []
                    # If strict-dynamic, nonce, or hashes are used, unsafe-inline in script-src is overridden and ignored by browsers
                    if "unsafe-inline" in csp_lower and not (has_strict_dynamic or has_nonce or has_hashes):
                        weaknesses.append("unsafe-inline allowed in script-src/style-src without nonce/hash/strict-dynamic protection")
                    if "unsafe-eval" in csp_lower:
                        weaknesses.append("unsafe-eval allowed in script-src")
                    if "*" in csp_lower.replace("https://*", "").replace("http://*", ""):
                        weaknesses.append("wildcard '*' source allowed")

                    if weaknesses:
                        conf = confidence_for_header_finding(True, csp)
                        cvss = get_cvss("weak_csp")
                        mitre = get_mitre_mapping("xss")
                        findings.append({
                            "title": "Weak Content-Security-Policy Policy",
                            "severity": "Low",
                            "confidence": conf["confidence"],
                            **{k: v for k, v in conf.items() if k != "confidence"},
                            "evidence": f"CSP: {csp}",
                            "http_status": resp.status_code,
                            "affected_url": str(resp.url),
                            "scanner_name": "HeaderScanner",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": resp.request.method,
                            "response_headers": str(dict(headers))[:200],
                            "response_snippet": "",
                            "matched_payload": "N/A",
                            "matched_header": "Content-Security-Policy",
                            "owasp_mapping": "A05:2021-Security Misconfiguration",
                            "cwe_mapping": "CWE-1021",
                            "cvss_estimate": str(cvss.get("base_score", "3.8")),
                            "cvss_vector": cvss.get("vector", ""),
                            "mitre_attack": mitre,
                            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                            "description": f"The CSP header contains weak configuration directives: {', '.join(weaknesses)}.",
                            "recommendation": "Refine the CSP policy to avoid unsafe-inline or wildcards in script-src directives."
                        })
                        if severity == "Informational":
                            severity = "Low"
                            status = "warning"

            # 2. HSTS Inspection
            hsts = headers.get("Strict-Transport-Security")
            if not hsts:
                conf = confidence_for_header_finding(False)
                cvss = get_cvss("missing_hsts")
                mitre = get_mitre_mapping("missing_https")
                findings.append({
                    "title": "Missing Strict-Transport-Security Header",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    **{k: v for k, v in conf.items() if k != "confidence"},
                    "evidence": "No Strict-Transport-Security header found.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-523",
                    "cvss_estimate": str(cvss.get("base_score", "3.1")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                    "description": "Strict-Transport-Security (HSTS) header is missing, allowing connection downgrades.",
                    "recommendation": "Configure Strict-Transport-Security header with max-age >= 15768000 and includeSubDomains."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"
            else:
                import re
                hsts_lower = hsts.lower()
                max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts_lower)
                weak_hsts = []
                has_max_age_error = False
                has_subdomains_error = False
                has_preload_error = False

                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 15768000:
                        weak_hsts.append(f"max-age is low ({max_age} < 15768000)")
                        has_max_age_error = True
                else:
                    weak_hsts.append("missing max-age directive")
                    has_max_age_error = True

                if "includesubdomains" not in hsts_lower:
                    weak_hsts.append("missing includeSubDomains directive")
                    has_subdomains_error = True
                if "preload" not in hsts_lower:
                    has_preload_error = True

                # Report suboptimal HSTS
                if has_max_age_error or has_subdomains_error:
                    conf = confidence_for_header_finding(True, hsts)
                    findings.append({
                        "title": "Suboptimal HSTS Configuration",
                        "severity": "Low",
                        "confidence": conf["confidence"],
                        **{k: v for k, v in conf.items() if k != "confidence"},
                        "evidence": f"HSTS: {hsts}. Errors: {', '.join(weak_hsts)}",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "HeaderScanner",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "response_headers": str(dict(headers))[:200],
                        "response_snippet": "",
                        "matched_payload": "N/A",
                        "matched_header": "Strict-Transport-Security",
                        "owasp_mapping": "A05:2021-Security Misconfiguration",
                        "cwe_mapping": "CWE-523",
                        "cvss_estimate": "3.1" if has_max_age_error else "2.1",
                        "references": ["https://hstspreload.org/"],
                        "description": f"The Strict-Transport-Security header configuration has weaknesses: {', '.join(weak_hsts)}.",
                        "recommendation": "Increase HSTS max-age to 31536000 (1 year) and ensure includeSubDomains is enabled."
                    })
                    if severity == "Informational":
                        severity = "Low"
                        status = "warning"

                if has_preload_error and not (has_max_age_error or has_subdomains_error):
                    # Report missing preload independently as Informational (not a vulnerability)
                    conf = confidence_for_header_finding(True, hsts)
                    findings.append({
                        "title": "HSTS Preload Submission Recommended",
                        "severity": "Informational",
                        "confidence": conf["confidence"],
                        **{k: v for k, v in conf.items() if k != "confidence"},
                        "evidence": f"HSTS: {hsts} (missing preload directive)",
                        "http_status": resp.status_code,
                        "affected_url": str(resp.url),
                        "scanner_name": "HeaderScanner",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": resp.request.method,
                        "description": "Strict-Transport-Security header is present and secure, but missing 'preload' which is recommended for browser submission.",
                        "recommendation": "Add the 'preload' directive to the HSTS header and submit the domain to hstspreload.org."
                    })

            # 3. X-Frame-Options
            csp_frame_ancestors = "frame-ancestors" in headers.get("Content-Security-Policy", "").lower()
            x_frame = headers.get("X-Frame-Options", "").lower()
            if not x_frame and not csp_frame_ancestors:
                conf = confidence_for_header_finding(False)
                cvss = get_cvss("missing_x_frame_options")
                findings.append({
                    "title": "Missing Anti-Clickjacking Protections",
                    "severity": "Medium",
                    "confidence": conf["confidence"],
                    "evidence": "No X-Frame-Options header and no CSP frame-ancestors directive found.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-1021",
                    "cvss_estimate": str(cvss.get("base_score", "6.1")),
                    "cvss_vector": cvss.get("vector", ""),
                    "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
                    "description": "Neither X-Frame-Options nor CSP frame-ancestors is present to restrict framing.",
                    "recommendation": "Configure X-Frame-Options to DENY or SAMEORIGIN, or configure frame-ancestors in CSP."
                })
                severity = "Medium"
                status = "warning"
            elif x_frame and x_frame not in ("deny", "sameorigin") and not x_frame.startswith("allow-from"):
                conf = confidence_for_header_finding(True, x_frame)
                findings.append({
                    "title": "Weak X-Frame-Options Configuration",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": f"X-Frame-Options: {x_frame}",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "X-Frame-Options",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-1021",
                    "cvss_estimate": "3.1",
                    "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
                    "description": f"X-Frame-Options header contains a non-standard or weak directive: '{x_frame}'.",
                    "recommendation": "Configure X-Frame-Options header strictly to DENY or SAMEORIGIN."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"

            # 4. Referrer-Policy
            referrer_policy = headers.get("Referrer-Policy", "").lower()
            if not referrer_policy:
                conf = confidence_for_header_finding(False)
                findings.append({
                    "title": "Missing Referrer-Policy Header",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": "No Referrer-Policy header found.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-200",
                    "cvss_estimate": "3.1",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                    "description": "Referrer-Policy header is missing. The browser default might leak referrer details to third-party domains.",
                    "recommendation": "Configure Referrer-Policy header to 'strict-origin-when-cross-origin' or 'no-referrer'."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"
            elif referrer_policy == "unsafe-url" or "no-referrer-when-downgrade" in referrer_policy:
                conf = confidence_for_header_finding(True, referrer_policy)
                findings.append({
                    "title": "Weak Referrer-Policy Header Configuration",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": f"Referrer-Policy: {referrer_policy}",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "Referrer-Policy",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-200",
                    "cvss_estimate": "2.6",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                    "description": f"The Referrer-Policy is configured to a weak value ('{referrer_policy}') that might leak internal URLs.",
                    "recommendation": "Configure Referrer-Policy strictly to 'strict-origin-when-cross-origin' or 'no-referrer'."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"

            # 5. Permissions-Policy
            permissions_policy = headers.get("Permissions-Policy")
            if not permissions_policy:
                conf = confidence_for_header_finding(False)
                findings.append({
                    "title": "Missing Permissions-Policy Header",
                    "severity": "Informational",
                    "confidence": conf["confidence"],
                    "evidence": "No Permissions-Policy header found.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-693",
                    "cvss_estimate": "0.0",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                    "description": "Permissions-Policy header is missing, leaving browser API features unconstrained.",
                    "recommendation": "Implement Permissions-Policy header to lock down access to APIs like geolocation, camera, or microphone."
                })

            # 6. X-Content-Type-Options
            x_content_type = headers.get("X-Content-Type-Options", "").lower()
            if "nosniff" not in x_content_type:
                conf = confidence_for_header_finding(False)
                cvss = get_cvss("missing_x_content_type")
                findings.append({
                    "title": "Missing X-Content-Type-Options Header",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": "X-Content-Type-Options: nosniff header is missing.",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-116",
                    "cvss_estimate": str(cvss.get("base_score", "4.3")),
                    "cvss_vector": cvss.get("vector", ""),
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                    "description": "X-Content-Type-Options header is missing, permitting browser MIME-type sniffing.",
                    "recommendation": "Configure X-Content-Type-Options header with 'nosniff' directive."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"

            # 7. Cache-Control
            cache_control = headers.get("Cache-Control", "").lower()
            if is_html and ("no-store" not in cache_control and "private" not in cache_control):
                conf = confidence_for_header_finding(True, cache_control)
                findings.append({
                    "title": "Suboptimal Cache-Control Configuration",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": f"Cache-Control: {cache_control}",
                    "http_status": resp.status_code,
                    "affected_url": str(resp.url),
                    "scanner_name": "HeaderScanner",
                    "detection_method": "Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": resp.request.method,
                    "response_headers": str(dict(headers))[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "Cache-Control",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-524",
                    "cvss_estimate": "2.1",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"],
                    "description": "Cache-Control does not restrict caching of sensitive HTML data (missing 'no-store' or 'private').",
                    "recommendation": "Ensure sensitive pages return Cache-Control: no-store, no-cache, private."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"

        except Exception as e:
            logger.error(f"HeaderScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Header Inspection Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": url,
                "scanner_name": "HeaderScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform real-time header scan on {target}. Error: {str(e)}",
                "recommendation": "Verify target accessibility and check HTTP headers manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"HeaderScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "HeaderScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
