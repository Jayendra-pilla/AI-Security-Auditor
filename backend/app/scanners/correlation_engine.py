import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def correlate_findings(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates findings across different scanners to adjust severity,
    increase confidence, and note combined exploit chains (Phase 6).
    """
    logger.info("Running Cross-Scanner Correlation Engine...")
    
    # 1. Collate all findings into a flat list for cross-referencing
    all_findings: List[Dict[str, Any]] = []
    
    scanner_results = results.get("results", [])
    for res in scanner_results:
        if isinstance(res, dict) and res.get("status") == "success":
            findings_data = res.get("findings", [])
            if isinstance(findings_data, list):
                all_findings.extend(findings_data)
            elif isinstance(findings_data, dict):
                all_findings.append(findings_data)

    # Flags to check presence
    has_missing_csp = False
    has_reflected_xss = False
    has_missing_hsts = False
    has_weak_cookies = False
    has_swagger = False
    has_exposed_api = False
    has_open_redirect = False
    has_oauth = False

    # Inspect all findings
    for f in all_findings:
        title = f.get("title", "").lower()
        desc = f.get("description", "").lower()
        evidence = f.get("evidence", "").lower()
        affected_url = f.get("affected_url", "").lower()

        if "content-security-policy" in title or "content-security-policy" in desc or "csp" in title:
            if "missing" in title or "missing" in desc:
                has_missing_csp = True
        
        if "cross-site scripting" in title or "xss" in title:
            has_reflected_xss = True
            
        if "strict-transport-security" in title or "hsts" in title:
            if "missing" in title or "missing" in desc:
                has_missing_hsts = True
                
        if "cookie" in title and ("insecure" in title or "missing" in title or "flag" in desc):
            has_weak_cookies = True
            
        if "swagger" in title or "openapi" in title:
            has_swagger = True
            
        if "api endpoints" in title or "exposed api" in title:
            has_exposed_api = True
            
        if "open redirect" in title or "redirection" in desc:
            has_open_redirect = True
            
        if "oauth" in affected_url or "authorize" in affected_url or "callback" in affected_url:
            has_oauth = True

    # 2. Apply Correlation Rules and upgrade findings in place
    for res in scanner_results:
        if not isinstance(res, dict) or res.get("status") != "success":
            continue
        findings_data = res.get("findings", [])
        
        # Helper normalization to list
        is_dict = False
        if isinstance(findings_data, dict):
            findings_data = [findings_data]
            is_dict = True
            
        if not isinstance(findings_data, list):
            continue

        for f in findings_data:
            title_lower = f.get("title", "").lower()
            desc_lower = f.get("description", "").lower()
            affected_url_lower = f.get("affected_url", "").lower()

            # Rule A: Missing CSP + Reflected XSS -> Upgrade XSS confidence to High (98%)
            if has_missing_csp and has_reflected_xss and ("xss" in title_lower or "cross-site scripting" in title_lower):
                f["confidence"] = "High"
                f["confidence_score"] = 98
                f["reliability_score"] = 0.98
                f["false_positive_probability"] = 0.02
                f["description"] = f.get("description", "") + "\n\n• **[CORRELATION NOTE]**: Reflected XSS confidence upgraded to High (98%) due to lack of Content-Security-Policy (CSP) mitigations on the host."

            # Rule B: Weak Cookies + Missing HSTS -> Upgrade cookie risk to Medium/High
            if has_weak_cookies and has_missing_hsts and "cookie" in title_lower:
                f["severity"] = "Medium"
                f["description"] = f.get("description", "") + "\n\n• **[CORRELATION NOTE]**: Risk escalated to Medium. Insecure cookie flag configuration combined with lack of HSTS exposes session cookies to plain HTTP MITM hijacking."

            # Rule C: Swagger + Exposed API -> Upgrade Swagger exposure severity
            if has_swagger and has_exposed_api and ("swagger" in title_lower or "openapi" in title_lower):
                f["severity"] = "High"
                f["cvss_estimate"] = "7.5"
                f["description"] = f.get("description", "") + "\n\n• **[CORRELATION NOTE]**: Escalated to High severity. Exposing Swagger documentation alongside actively accessible API endpoints allows automated discovery of sensitive endpoints."

            # Rule D: Open Redirect + OAuth Endpoint -> Upgrade Open Redirect severity
            if has_open_redirect and has_oauth and "open redirect" in title_lower:
                f["severity"] = "Critical"
                f["cvss_estimate"] = "9.3"
                f["description"] = f.get("description", "") + "\n\n• **[CORRELATION NOTE]**: Critical Risk! Open redirection vulnerability combined with OAuth endpoints permits theft of authentication codes and token hijack exploits."

        if is_dict:
            res["findings"] = findings_data[0]

    return results
