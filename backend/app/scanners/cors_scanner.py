from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
import urllib.parse
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class CORSScanner:
    """
    Scanner to inspect Cross-Origin Resource Sharing (CORS) configurations.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"CORSScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            parsed_target = urllib.parse.urlparse(url)
            target_host = parsed_target.hostname or target

            test_origins = [
                "https://evil.com",
                "null",
                "file://",
                "http://localhost",
                "http://127.0.0.1",
                f"https://{target_host}evil.com",  # Regex suffix bypass
                f"https://evil{target_host}",      # Regex prefix bypass
                f"https://sub.{target_host}",      # Subdomain trust check
            ]
            reflected_origins = []
            wildcard_credentials = False
            missing_vary = False
            unsafe_credentials = False
            evidence_headers = {}

            with SafeHTTPClient(timeout=2.0) as client:
                for origin in test_origins:
                    try:
                        resp = client.get(url, headers={"Origin": origin}, follow_redirects=True)
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                        vary = resp.headers.get("Vary", "")

                        evidence_headers[origin] = {
                            "ACAO": acao,
                            "ACAC": acac,
                            "Vary": vary
                        }

                        # Check for wildcard + credentials
                        if acao == "*" and acac == "true":
                            wildcard_credentials = True

                        # Check for origin reflection
                        if acao == origin:
                            reflected_origins.append(origin)
                            if acac == "true":
                                unsafe_credentials = True
                            
                            # Check if Vary is missing Origin
                            if "origin" not in vary.lower():
                                missing_vary = True

                    except Exception as req_err:
                        logger.debug(f"CORS request failed for origin {origin}: {str(req_err)}")

            # Report findings
            # 1. Unsafe Credential Sharing via dynamic reflection
            if unsafe_credentials:
                cvss = get_cvss("cors_reflected_origin")
                mitre = get_mitre_mapping("cors_misconfiguration")
                conf = calculate_confidence(
                    validation_methods=["Payload Reflection", "Header Validation"],
                    evidence_quality="high",
                    multiple_confirmations=len(reflected_origins)
                )
                findings.append({
                    "title": "Unsafe Dynamic CORS Policy (Credentials Allowed)",
                    "severity": "High",
                    "confidence": conf["confidence"],
                    "evidence": f"Reflected origins: {reflected_origins}. Access-Control-Allow-Credentials is true.",
                    "http_status": 200,
                    "affected_url": url,
                    "scanner_name": "CORSScanner",
                    "detection_method": "Dynamic Origin Reflection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(evidence_headers)[:200],
                    "matched_payload": "Origin: https://evil.com",
                    "matched_header": "Access-Control-Allow-Origin",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-942",
                    "cvss_estimate": str(cvss.get("base_score", "7.5")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://portswigger.net/web-security/cors"],
                    "description": "The application dynamically reflects unauthorized Origin headers (e.g. evil.com) and enables Access-Control-Allow-Credentials: true. This allows external sites to execute authenticated API queries and steal user data.",
                    "recommendation": "Never dynamically echo the Origin header when credentials are allowed. Validate incoming origins against a strict whitelist."
                })
                severity = "High"
                status = "warning"

            # 2. Wildcard + Credentials (invalid but permissive configuration)
            elif wildcard_credentials:
                cvss = get_cvss("cors_wildcard_credentials")
                mitre = get_mitre_mapping("cors_misconfiguration")
                conf = calculate_confidence(
                    validation_methods=["Header Validation"],
                    evidence_quality="high"
                )
                findings.append({
                    "title": "Invalid CORS Configuration (Wildcard and Credentials)",
                    "severity": "Medium",
                    "confidence": conf["confidence"],
                    "evidence": "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true",
                    "http_status": 200,
                    "affected_url": url,
                    "scanner_name": "CORSScanner",
                    "detection_method": "Origin Header Injection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(evidence_headers)[:200],
                    "matched_payload": "N/A",
                    "matched_header": "Access-Control-Allow-Origin",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-942",
                    "cvss_estimate": str(cvss.get("base_score", "4.8")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotAllowingCredentials"],
                    "description": "The CORS headers allow wildcard origin '*' with credentials enabled. Modern browsers block this combo, but client applications or proxy servers may bypass browser restrictions.",
                    "recommendation": "Remove Access-Control-Allow-Credentials: true if wildcard origin is intended, or use explicit whitelisted origins instead."
                })
                if severity != "High":
                    severity = "Medium"
                    status = "warning"

            # 3. Permissive Dynamic Reflection (no credentials)
            elif reflected_origins:
                cvss = get_cvss("cors_reflected_origin")
                mitre = get_mitre_mapping("cors_misconfiguration")
                conf = calculate_confidence(
                    validation_methods=["Payload Reflection"],
                    evidence_quality="medium",
                    multiple_confirmations=len(reflected_origins)
                )
                findings.append({
                    "title": "Permissive Dynamic CORS Policy (No Credentials)",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": f"Reflected origins: {reflected_origins}.",
                    "http_status": 200,
                    "affected_url": url,
                    "scanner_name": "CORSScanner",
                    "detection_method": "Dynamic Origin Reflection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(evidence_headers)[:200],
                    "matched_payload": "Origin: https://evil.com",
                    "matched_header": "Access-Control-Allow-Origin",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-942",
                    "cvss_estimate": str(cvss.get("base_score", "3.1")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://portswigger.net/web-security/cors"],
                    "description": "The server dynamically reflects any Origin header (e.g. evil.com), but does not permit credentials. This allows public access but raises caching concerns.",
                    "recommendation": "Define a strict list of allowed origins rather than mirroring input origins."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"

            # 4. Missing Vary header
            if reflected_origins and missing_vary:
                conf = calculate_confidence(
                    validation_methods=["Header Validation"],
                    evidence_quality="medium"
                )
                findings.append({
                    "title": "CORS Policy Missing Vary: Origin Header",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    "evidence": "Access-Control-Allow-Origin is reflected but 'Vary: Origin' is missing in response headers.",
                    "http_status": 200,
                    "affected_url": url,
                    "scanner_name": "CORSScanner",
                    "detection_method": "Response Header Inspection",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(evidence_headers)[:200],
                    "matched_payload": "N/A",
                    "matched_header": "Vary",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-524",
                    "cvss_estimate": "3.1",
                    "references": ["https://portswigger.net/web-security/cors/preflight-cache-poisoning"],
                    "description": "The server reflects origin values but does not send 'Vary: Origin'. This can cause proxy caches to store CORS headers and poison responses to other clients.",
                    "recommendation": "Configure the web server to append 'Vary: Origin' to response headers whenever CORS is dynamic."
                })
                if severity == "Informational":
                    severity = "Low"
                    status = "warning"

            # Baseline clean check
            if not findings:
                findings.append({
                    "title": "CORS Policies Verified",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Tested origins were not echoed, and no wildcard credential configurations were found.",
                    "http_status": 200,
                    "affected_url": url,
                    "scanner_name": "CORSScanner",
                    "detection_method": "Origin Header Injection",
                    "timestamp": datetime_now_utc_str(),
                    "description": "CORS validation checks are complete. No unsafe or dynamic credential sharing configurations were detected.",
                    "recommendation": "Continue maintaining strict host whitelisting."
                })

        except Exception as e:
            logger.error(f"CORSScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "CORS Check Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": url,
                "scanner_name": "CORSScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform CORS test on {target}. Error: {str(e)}",
                "recommendation": "Check CORS configurations on target gateway or servers."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"CORSScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "CORSScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
