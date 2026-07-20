from app.observability.ssrf_prevention import SafeHTTPClient
import time
import json
import logging
from urllib.parse import urljoin
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)


def _validate_swagger(body: str, content_type: str) -> int:
    """
    Count how many independent Swagger/OpenAPI signatures are present.
    Returns signature match count (need ≥2 to confirm).
    """
    body_lower = body.lower()
    ct_lower = content_type.lower()
    score = 0

    # Swagger UI assets
    if "swagger-ui.css" in body_lower:
        score += 1
    if "swagger-ui-bundle.js" in body_lower:
        score += 1
    # Swagger HTML title
    if "<title>swagger ui</title>" in body_lower or "<title>swagger</title>" in body_lower:
        score += 1
    # OpenAPI/Swagger JSON reference
    if "openapi.json" in body_lower or "swagger.json" in body_lower or "swagger-config" in body_lower:
        score += 1
    # JSON content with openapi/swagger key
    if "application/json" in ct_lower:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and ("openapi" in parsed or "swagger" in parsed):
                score += 2  # Strong signal
        except (json.JSONDecodeError, ValueError):
            pass

    return score


def _validate_graphql(body: str, content_type: str) -> int:
    """
    Count how many independent GraphQL signatures are present.
    Returns signature match count (need ≥2 to confirm).
    """
    body_lower = body.lower()
    ct_lower = content_type.lower()
    score = 0

    # GraphiQL HTML interface
    if "graphiql" in body_lower:
        score += 1
    # Apollo sandbox / explorer
    if "apollo" in body_lower and ("sandbox" in body_lower or "explorer" in body_lower):
        score += 1
    # GraphQL playground
    if "graphql playground" in body_lower or "graphql-playground" in body_lower:
        score += 1
    # Introspection schema keys
    if "__schema" in body_lower or "__typename" in body_lower:
        score += 1
    # JSON content with data key (typical GraphQL response)
    if "application/json" in ct_lower:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                if "data" in parsed and "__schema" in str(parsed.get("data", "")):
                    score += 2  # Strong signal
        except (json.JSONDecodeError, ValueError):
            pass
    # GraphQL in title
    if "<title>graphql</title>" in body_lower or "<title>graphiql</title>" in body_lower:
        score += 1

    return score


class APIEndpointScanner:
    """
    Scanner to detect open API paths and public routing documentations.
    
    Requires multi-signature validation: Swagger/OpenAPI and GraphQL endpoints
    are only reported when ≥2 independent signatures confirm the detection.
    Generic HTML pages are never reported as API endpoints.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"APIEndpointScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

            # Categorize endpoints by type for targeted validation
            swagger_endpoints = ["/swagger", "/swagger.json", "/swagger/index.html", "/openapi.json", "/docs", "/api-docs", "/redoc"]
            graphql_endpoints = ["/graphql", "/api/graphql", "/graphql/console"]
            api_endpoints = ["/api", "/api/v1", "/api/v2"]

            confirmed_swagger = []
            confirmed_graphql = []
            confirmed_api = []
            evidence_data = {}

            with SafeHTTPClient(timeout=2.0) as client:
                # ── Swagger / OpenAPI Validation ──────────────────────
                swagger_signature_total = 0
                for ep in swagger_endpoints:
                    ep_url = urljoin(base_url.rstrip("/") + "/", ep.lstrip("/"))
                    try:
                        resp = client.get(ep_url, follow_redirects=True)
                        if resp.status_code in (200, 401, 403):
                            content_type = resp.headers.get("Content-Type", "")
                            body = resp.text

                            sig_count = _validate_swagger(body, content_type)
                            swagger_signature_total += sig_count

                            if sig_count >= 2:
                                confirmed_swagger.append(ep)
                                evidence_data[ep] = {
                                    "status_code": resp.status_code,
                                    "content_type": content_type,
                                    "signatures_matched": sig_count,
                                }
                            elif resp.status_code in (401, 403) and ep in ("/swagger.json", "/openapi.json", "/api-docs"):
                                # Auth-protected API doc — still counts as exposed
                                confirmed_swagger.append(ep)
                                evidence_data[ep] = {
                                    "status_code": resp.status_code,
                                    "content_type": content_type,
                                    "note": "Authentication required but endpoint exists",
                                }
                    except Exception as req_err:
                        logger.debug(f"Swagger probe failed for {ep}: {str(req_err)}")

                # ── GraphQL Validation ────────────────────────────────
                graphql_signature_total = 0
                for ep in graphql_endpoints:
                    ep_url = urljoin(base_url.rstrip("/") + "/", ep.lstrip("/"))
                    try:
                        resp = client.get(ep_url, follow_redirects=True)
                        if resp.status_code in (200, 400, 401, 403, 405):
                            content_type = resp.headers.get("Content-Type", "")
                            body = resp.text

                            sig_count = _validate_graphql(body, content_type)
                            graphql_signature_total += sig_count

                            if sig_count >= 2:
                                confirmed_graphql.append(ep)
                                evidence_data[ep] = {
                                    "status_code": resp.status_code,
                                    "content_type": content_type,
                                    "signatures_matched": sig_count,
                                }
                            elif resp.status_code == 405:
                                # GraphQL typically rejects GET with 405 (POST-only)
                                confirmed_graphql.append(ep)
                                evidence_data[ep] = {
                                    "status_code": 405,
                                    "content_type": content_type,
                                    "note": "POST-only GraphQL endpoint (405 on GET)",
                                }
                    except Exception as req_err:
                        logger.debug(f"GraphQL probe failed for {ep}: {str(req_err)}")

                # ── Generic API Endpoint Validation ───────────────────
                for ep in api_endpoints:
                    ep_url = urljoin(base_url.rstrip("/") + "/", ep.lstrip("/"))
                    try:
                        resp = client.get(ep_url, follow_redirects=True)
                        if resp.status_code in (200, 401, 403, 405):
                            content_type = resp.headers.get("Content-Type", "").lower()

                            # Only count as confirmed API if response is JSON
                            if "application/json" in content_type:
                                confirmed_api.append(ep)
                                evidence_data[ep] = {
                                    "status_code": resp.status_code,
                                    "content_type": content_type,
                                }
                            elif resp.status_code in (401, 403):
                                # Auth-protected API endpoint
                                confirmed_api.append(ep)
                                evidence_data[ep] = {
                                    "status_code": resp.status_code,
                                    "content_type": content_type,
                                    "note": "Endpoint returns auth error, confirming API presence",
                                }
                    except Exception as req_err:
                        logger.debug(f"API probe failed for {ep}: {str(req_err)}")

            # ── Report confirmed findings ─────────────────────────────
            if confirmed_swagger:
                validation_methods = ["Signature Matching", "Content-Type Validation"]
                if swagger_signature_total >= 4:
                    validation_methods.append("HTML Structure Analysis")
                conf = calculate_confidence(
                    validation_methods=validation_methods,
                    evidence_quality="high" if swagger_signature_total >= 4 else "medium",
                    multiple_confirmations=len(confirmed_swagger),
                )
                cvss = get_cvss("api_endpoint_exposed")
                mitre = get_mitre_mapping("api_exposure")
                findings.append({
                    "title": "Publicly Accessible Swagger/OpenAPI Documentation",
                    "severity": "Medium",
                    "confidence": conf["confidence"],
                    "evidence": f"Confirmed Swagger endpoints (≥2 signatures each): {confirmed_swagger}. Details: {evidence_data}",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "APIEndpointScanner",
                    "detection_method": "Multi-Signature Swagger Validation",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-306",
                    "cvss_estimate": str(cvss.get("base_score", "5.3")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://owasp.org/www-project-api-security/"],
                    "description": f"Swagger/OpenAPI documentation is publicly accessible at: {', '.join(confirmed_swagger)}. Validated with multiple independent signature checks.",
                    "recommendation": "Restrict API documentation access to authenticated users or internal networks. Remove Swagger UI from production deployments."
                })
                severity = "Medium"
                status = "warning"

            if confirmed_graphql:
                validation_methods = ["Signature Matching", "Content-Type Validation"]
                if graphql_signature_total >= 4:
                    validation_methods.append("JSON Schema Validation")
                conf = calculate_confidence(
                    validation_methods=validation_methods,
                    evidence_quality="high" if graphql_signature_total >= 4 else "medium",
                    multiple_confirmations=len(confirmed_graphql),
                )
                cvss = get_cvss("api_endpoint_exposed")
                mitre = get_mitre_mapping("api_exposure")
                findings.append({
                    "title": "Publicly Accessible GraphQL Endpoint",
                    "severity": "Medium",
                    "confidence": conf["confidence"],
                    "evidence": f"Confirmed GraphQL endpoints (≥2 signatures each): {confirmed_graphql}. Details: {evidence_data}",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "APIEndpointScanner",
                    "detection_method": "Multi-Signature GraphQL Validation",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-306",
                    "cvss_estimate": str(cvss.get("base_score", "5.3")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://owasp.org/www-project-api-security/"],
                    "description": f"GraphQL endpoint is publicly accessible at: {', '.join(confirmed_graphql)}. Validated with multiple independent checks.",
                    "recommendation": "Disable GraphQL introspection in production. Require authentication for all GraphQL queries. Implement query complexity limits."
                })
                severity = "Medium"
                status = "warning"

            if confirmed_api:
                conf = calculate_confidence(
                    validation_methods=["Content-Type Validation", "Response Code Validation"],
                    evidence_quality="medium",
                    multiple_confirmations=len(confirmed_api),
                )
                findings.append({
                    "title": "Publicly Accessible API Endpoints",
                    "severity": "Informational",
                    "confidence": conf["confidence"],
                    "evidence": f"Confirmed API endpoints (JSON response): {confirmed_api}. Details: {evidence_data}",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "APIEndpointScanner",
                    "detection_method": "API Response Validation",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "description": f"API endpoints responding with JSON detected at: {', '.join(confirmed_api)}.",
                    "recommendation": "Verify all API endpoints require proper authentication and authorization."
                })

            if not findings:
                findings.append({
                    "title": "API Endpoint Scans Clean",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Tested Swagger, OpenAPI, GraphQL, and generic API endpoints. No verified API documentation or JSON API responses found.",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "APIEndpointScanner",
                    "detection_method": "Multi-Signature Endpoint Validation",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Tested common API and documentation paths with multi-signature validation. No open API resources confirmed.",
                    "recommendation": "Implement strict route validation and rate limiting on all endpoints."
                })
        except Exception as e:
            logger.error(f"APIEndpointScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "API Probing Failure",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": target,
                "scanner_name": "APIEndpointScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Failed to test API directories on target. Error: {str(e)}",
                "recommendation": "Manually inspect active endpoints and trace server routes."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"APIEndpointScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "APIEndpointScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
