from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
import urllib.parse
from app.scanners.scanner_utils import get_tech_fingerprint, datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class XSSScanner:
    """
    Scanner to detect potential Reflected Cross-Site Scripting (XSS) exposures.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"XSSScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            
            # Smart Technology & WAF Check
            tech = get_tech_fingerprint(target)
            has_waf = tech["waf"] is not None

            # Metacharacter-heavy XSS Probe Payload
            xss_payload = 'xss"\'><script>alert(1)</script>'
            test_url = f"{url}?q={urllib.parse.quote(xss_payload)}"
            
            with SafeHTTPClient(timeout=3.0) as client:
                resp = client.get(test_url, follow_redirects=True)
            
            body = resp.text
            
            if "xss" in body.lower():
                # Analyze context and sanitization
                is_unescaped = xss_payload in body
                is_html_encoded = ("&lt;script&gt;" in body) or ("&amp;lt;" in body)
                is_quote_escaped = ("\\\"" in body) or ("\\'" in body) or ("&quot;" in body)

                # Determine reflection context
                context = "HTML Body"
                idx = body.find("xss")
                if idx != -1:
                    pre_snippet = body[max(0, idx-50):idx]
                    post_snippet = body[idx:min(len(body), idx+100)]
                    
                    if "<script" in pre_snippet.lower() or "javascript:" in pre_snippet.lower():
                        context = "Script Block"
                    elif '="' in pre_snippet or "='" in pre_snippet or 'href=' in pre_snippet.lower():
                        context = "Attribute Context"
                    elif "style=" in pre_snippet.lower():
                        context = "CSS Context"

                # Check CSP block
                csp = resp.headers.get("Content-Security-Policy", "")
                csp_blocks_inline = "script-src" in csp.lower() and "'unsafe-inline'" not in csp.lower()

                # Assessment
                if is_unescaped and not is_html_encoded:
                    if csp_blocks_inline:
                        cvss = get_cvss("reflected_xss")
                        mitre = get_mitre_mapping("xss")
                        conf = calculate_confidence(
                            validation_methods=["Payload Reflection", "Content Validation", "Header Validation"],
                            evidence_quality="medium",
                        )
                        findings.append({
                            "title": "Unescaped Input Reflection Mitigated by CSP",
                            "severity": "Medium",
                            "confidence": conf["confidence"],
                            "evidence": f"Reflected snippet: {post_snippet[:50]}. CSP: {csp}",
                            "http_status": resp.status_code,
                            "affected_url": test_url,
                            "scanner_name": "XSSScanner",
                            "detection_method": "XSS Payload Reflection Analysis",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": "GET",
                            "response_headers": str(dict(resp.headers))[:200],
                            "response_snippet": body[max(0, idx-20):min(len(body), idx+80)][:200],
                            "matched_payload": xss_payload,
                            "matched_header": "N/A",
                            "owasp_mapping": "A03:2021-Injection",
                            "cwe_mapping": "CWE-79",
                            "cvss_estimate": str(cvss.get("base_score", "6.1")),
                            "cvss_vector": cvss.get("vector", ""),
                            "mitre_attack": mitre,
                            "references": ["https://owasp.org/www-community/attacks/xss/"],
                            "description": f"The query parameter was reflected unescaped in {context}. Although execution is restricted by the browser due to CSP, the server-side reflection itself should be sanitized.",
                            "recommendation": "Perform context-aware HTML entity encoding on all reflected values on the server."
                        })
                        severity = "Medium"
                        status = "warning"
                    elif has_waf:
                        cvss = get_cvss("reflected_xss")
                        mitre = get_mitre_mapping("xss")
                        conf = calculate_confidence(
                            validation_methods=["Payload Reflection", "Content Validation"],
                            evidence_quality="low",
                            response_consistent=True,
                        )
                        findings.append({
                            "title": "Potential Reflected XSS (WAF Detected)",
                            "severity": "Medium",
                            "confidence": conf["confidence"],
                            "evidence": f"Reflected unescaped snippet: {post_snippet[:50]}. WAF: {tech['waf']}",
                            "http_status": resp.status_code,
                            "affected_url": test_url,
                            "scanner_name": "XSSScanner",
                            "detection_method": "XSS Payload Reflection Analysis",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": "GET",
                            "response_headers": str(dict(resp.headers))[:200],
                            "response_snippet": body[max(0, idx-20):min(len(body), idx+80)][:200],
                            "matched_payload": xss_payload,
                            "matched_header": "N/A",
                            "owasp_mapping": "A03:2021-Injection",
                            "cwe_mapping": "CWE-79",
                            "cvss_estimate": str(cvss.get("base_score", "6.1")),
                            "cvss_vector": cvss.get("vector", ""),
                            "mitre_attack": mitre,
                            "references": ["https://owasp.org/www-community/attacks/xss/"],
                            "description": f"The injection payload was reflected raw in {context}. A WAF ({tech['waf']}) is active which might intercept larger exploits, but the underlying application remains vulnerable.",
                            "recommendation": "Enforce strict input sanitization and context-aware output encoding on all reflected values."
                        })
                        severity = "Medium"
                        status = "warning"
                    else:
                        cvss = get_cvss("reflected_xss_unescaped")
                        mitre = get_mitre_mapping("xss")
                        conf = calculate_confidence(
                            validation_methods=["Payload Reflection", "Content Validation"],
                            evidence_quality="high",
                            response_consistent=True,
                        )
                        findings.append({
                            "title": "Reflected Cross-Site Scripting (XSS)",
                            "severity": "High",
                            "confidence": conf["confidence"],
                            "evidence": f"Unescaped payload reflected in {context}: {post_snippet[:60]}",
                            "http_status": resp.status_code,
                            "affected_url": test_url,
                            "scanner_name": "XSSScanner",
                            "detection_method": "XSS Payload Reflection Analysis",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": "GET",
                            "response_headers": str(dict(resp.headers))[:200],
                            "response_snippet": body[max(0, idx-20):min(len(body), idx+80)][:200],
                            "matched_payload": xss_payload,
                            "matched_header": "N/A",
                            "owasp_mapping": "A03:2021-Injection",
                            "cwe_mapping": "CWE-79",
                            "cvss_estimate": str(cvss.get("base_score", "9.3")),
                            "cvss_vector": cvss.get("vector", ""),
                            "mitre_attack": mitre,
                            "references": ["https://owasp.org/www-community/attacks/xss/"],
                            "description": f"The XSS payload was reflected unescaped in {context}. This allows attackers to execute arbitrary JavaScript in the victim's browser context.",
                            "recommendation": "Implement context-aware HTML entity encoding on all user inputs before rendering them in the DOM."
                        })
                        severity = "High"
                        status = "warning"
                else:
                    conf = calculate_confidence(
                        validation_methods=["Payload Reflection", "Content Validation"],
                        evidence_quality="high",
                    )
                    findings.append({
                        "title": "Reflected Input Properly Escaped",
                        "severity": "Informational",
                        "confidence": conf["confidence"],
                        "evidence": f"HTML Encoded: {is_html_encoded}, Quote Escaped: {is_quote_escaped}.",
                        "http_status": resp.status_code,
                        "affected_url": test_url,
                        "scanner_name": "XSSScanner",
                        "detection_method": "XSS Payload Reflection Analysis",
                        "timestamp": datetime_now_utc_str(),
                        # No CVSS generated for Informational findings as per Phase 7
                        "description": "Input values were reflected but correctly sanitized or HTML-encoded by the server.",
                        "recommendation": "Continue following secure coding guidelines for output rendering."
                    })
            else:
                findings.append({
                    "title": "Reflected XSS Check Clean",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Tested URL query parameter reflection. No reflections detected.",
                    "http_status": resp.status_code,
                    "affected_url": test_url,
                    "scanner_name": "XSSScanner",
                    "detection_method": "XSS Payload Reflection Analysis",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Tested URL query parameter reflection. No reflections detected.",
                    "recommendation": "Continue validating inputs and escaping outputs globally."
                })
        except Exception as e:
            logger.error(f"XSSScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "XSS Probe Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": url,
                "scanner_name": "XSSScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform reflected XSS checks. Error: {str(e)}",
                "recommendation": "Audit application controllers and views manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"XSSScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "XSSScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
