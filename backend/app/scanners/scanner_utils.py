import urllib.parse
import socket
import ssl
import time
import logging
import re
from typing import Dict, Any, List, Optional
import httpx
import tldextract
from bs4 import BeautifulSoup
from app.observability.ssrf_prevention import SafeHTTPClient

logger = logging.getLogger(__name__)

# Cache for technology detection results to avoid duplicate requests across scanners
_tech_cache: Dict[str, Dict[str, Any]] = {}


def extract_root_domain(target: str) -> str:
    """
    Extract the registrable root domain from a target URL or hostname.
    Uses tldextract for proper Public Suffix List support.

    Examples:
        https://www.youtube.com → youtube.com
        https://blog.example.co.uk → example.co.uk
        https://app.service.gov.in → service.gov.in
        www.youtube.com → youtube.com
    """
    # Normalize: strip scheme if present to get hostname
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        hostname = parsed.hostname or target
    else:
        hostname = target.split("/")[0]

    extracted = tldextract.extract(hostname)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    # Fallback: return hostname as-is if extraction fails
    return hostname


def get_tech_fingerprint(target: str) -> Dict[str, Any]:
    """
    Fingerprint the target technology stack (Web Server, Framework, Language, WAF, CDN, etc.)
    and cache the result. Returns confidence scores per detection.
    """
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    parsed = urllib.parse.urlparse(url)
    cache_key = f"{parsed.scheme}://{parsed.netloc}"

    if cache_key in _tech_cache:
        return _tech_cache[cache_key]

    tech = {
        "web_server": None,
        "framework": None,
        "language": None,
        "cms": None,
        "waf": None,
        "cdn": None,
        "cloud_provider": None,
        "css_framework": None,
        "js_framework": None,
        "raw_headers": {},
        "raw_cookies": {},
        "html_signatures": [],
        "detection_confidence": {},
    }

    # Perform a safe GET request to capture headers and HTML body
    try:
        with SafeHTTPClient(timeout=3.0) as client:
            resp = client.get(url, follow_redirects=True)
            headers = resp.headers
            tech["raw_headers"] = dict(headers)
            tech["raw_cookies"] = dict(resp.cookies)
            html_content = resp.text
            html_lower = html_content.lower()

            # ── 1. Server header detection ─────────────────────────────
            server = headers.get("Server", "").lower()
            if "nginx" in server:
                _set_tech(tech, "web_server", "Nginx", "High")
            elif "apache" in server:
                _set_tech(tech, "web_server", "Apache", "High")
            elif "microsoft-iis" in server:
                _set_tech(tech, "web_server", "IIS", "High")
                _set_tech(tech, "language", "C#", "Medium")
                _set_tech(tech, "framework", "ASP.NET", "Medium")
            elif "litespeed" in server:
                _set_tech(tech, "web_server", "LiteSpeed", "High")
            elif "gunicorn" in server:
                _set_tech(tech, "web_server", "Gunicorn", "High")
                _set_tech(tech, "language", "Python", "Medium")
            elif "daphne" in server:
                _set_tech(tech, "web_server", "Daphne", "High")
                _set_tech(tech, "language", "Python", "Medium")
            elif "uvicorn" in server:
                _set_tech(tech, "web_server", "Uvicorn", "High")
                _set_tech(tech, "language", "Python", "Medium")

            # Cloudflare / CDN as server
            if "cloudflare" in server:
                _set_tech(tech, "cdn", "Cloudflare", "High")
                _set_tech(tech, "waf", "Cloudflare", "High")
            elif "akamaighost" in server or "akamai" in server:
                _set_tech(tech, "cdn", "Akamai", "High")

            # ── 2. X-Powered-By header ──────────────────────────────
            powered_by = headers.get("X-Powered-By", "").lower()
            if "php" in powered_by:
                _set_tech(tech, "language", "PHP", "High")
            elif "asp.net" in powered_by:
                _set_tech(tech, "language", "C#", "High")
                _set_tech(tech, "framework", "ASP.NET", "High")
            elif "express" in powered_by:
                _set_tech(tech, "language", "JavaScript", "High")
                _set_tech(tech, "framework", "Express", "High")
            elif "next.js" in powered_by or "nextjs" in powered_by:
                _set_tech(tech, "language", "JavaScript", "High")
                _set_tech(tech, "framework", "Next.js", "High")
            elif "nuxt" in powered_by:
                _set_tech(tech, "language", "JavaScript", "High")
                _set_tech(tech, "framework", "Nuxt", "High")

            # ── 3. WAF / CDN / Cloud detection from headers ─────────
            header_keys_lower = {k.lower() for k in headers.keys()}

            # Cloudflare
            if "cf-ray" in header_keys_lower or "cf-cache-status" in header_keys_lower:
                _set_tech(tech, "waf", "Cloudflare", "High")
                _set_tech(tech, "cdn", "Cloudflare", "High")

            # AWS
            if any(k.startswith("x-amz") for k in header_keys_lower):
                _set_tech(tech, "cloud_provider", "AWS", "High")
            if "x-amz-cf-id" in header_keys_lower or "x-amz-cf-pop" in header_keys_lower:
                _set_tech(tech, "cdn", "Amazon CloudFront", "High")
                _set_tech(tech, "cloud_provider", "AWS", "High")
            if "x-amz-waf-action" in header_keys_lower:
                _set_tech(tech, "waf", "AWS WAF", "High")

            # Azure
            if "x-azure-ref" in header_keys_lower:
                _set_tech(tech, "cloud_provider", "Azure", "High")
                _set_tech(tech, "cdn", "Azure Front Door", "Medium")
            if any(k.startswith("x-ms-") for k in header_keys_lower):
                _set_tech(tech, "cloud_provider", "Azure", "Medium")

            # GCP
            if any(k.startswith("x-goog-") for k in header_keys_lower):
                _set_tech(tech, "cloud_provider", "GCP", "Medium")
            if "via" in header_keys_lower and "google" in headers.get("via", "").lower():
                _set_tech(tech, "cloud_provider", "GCP", "Medium")

            # Fastly
            if "x-fastly-request-id" in header_keys_lower or "fastly" in server:
                _set_tech(tech, "cdn", "Fastly", "High")

            # Imperva / Incapsula
            if "x-iinfo" in header_keys_lower:
                _set_tech(tech, "waf", "Imperva", "High")
            if "x-cdn" in header_keys_lower and "imperva" in headers.get("x-cdn", "").lower():
                _set_tech(tech, "waf", "Imperva", "High")

            # Sucuri
            if "x-sucuri-id" in header_keys_lower or "x-sucuri-cache" in header_keys_lower:
                _set_tech(tech, "waf", "Sucuri", "High")

            # ── 4. Cookie detection ─────────────────────────────────
            cookies_lower = {k.lower(): v for k, v in resp.cookies.items()}
            all_cookie_names = set(cookies_lower.keys())

            if "phpsessid" in all_cookie_names:
                _set_tech(tech, "language", "PHP", "High")
            if "jsessionid" in all_cookie_names:
                _set_tech(tech, "language", "Java", "High")
            if any(k in all_cookie_names for k in ("asp.net_sessionid", "aspsessionid", ".aspxauth")):
                _set_tech(tech, "language", "C#", "High")
                _set_tech(tech, "framework", "ASP.NET", "High")
            if "laravel_session" in all_cookie_names:
                _set_tech(tech, "language", "PHP", "High")
                _set_tech(tech, "framework", "Laravel", "High")
            if "csrftoken" in all_cookie_names and "sessionid" in all_cookie_names:
                _set_tech(tech, "language", "Python", "High")
                _set_tech(tech, "framework", "Django", "High")
            elif "csrftoken" in all_cookie_names:
                _set_tech(tech, "language", "Python", "Medium")
                _set_tech(tech, "framework", "Django", "Medium")
            if "__cfduid" in all_cookie_names:
                _set_tech(tech, "waf", "Cloudflare", "Medium")
                _set_tech(tech, "cdn", "Cloudflare", "Medium")
            if "visid_incap" in all_cookie_names or "incap_ses" in all_cookie_names:
                _set_tech(tech, "waf", "Imperva", "High")
            if "aws-waf-token" in all_cookie_names:
                _set_tech(tech, "waf", "AWS WAF", "High")

            # ── 5. HTML meta / generator detection ──────────────────
            soup = BeautifulSoup(html_content, "html.parser")
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            if meta_gen:
                gen_content = (meta_gen.get("content") or "").lower()
                if "wordpress" in gen_content:
                    _set_tech(tech, "cms", "WordPress", "High")
                    _set_tech(tech, "language", "PHP", "High")
                elif "drupal" in gen_content:
                    _set_tech(tech, "cms", "Drupal", "High")
                    _set_tech(tech, "language", "PHP", "High")
                elif "joomla" in gen_content:
                    _set_tech(tech, "cms", "Joomla", "High")
                    _set_tech(tech, "language", "PHP", "High")
                elif "next.js" in gen_content:
                    _set_tech(tech, "framework", "Next.js", "High")
                    _set_tech(tech, "language", "JavaScript", "High")
                elif "nuxt" in gen_content:
                    _set_tech(tech, "framework", "Nuxt", "High")
                    _set_tech(tech, "language", "JavaScript", "High")

            # ── 6. HTML body / script / asset signature detection ───
            # CMS
            if "/wp-content/" in html_lower or "/wp-includes/" in html_lower:
                _set_tech(tech, "cms", "WordPress", "High")
                _set_tech(tech, "language", "PHP", "High")
            if "drupal.js" in html_lower or "drupal.min.js" in html_lower or 'data-drupal' in html_lower:
                _set_tech(tech, "cms", "Drupal", "High")
            if "/media/jui/" in html_lower or "/media/system/js/" in html_lower:
                _set_tech(tech, "cms", "Joomla", "Medium")

            # JS Frameworks
            _detected_js = set()
            if "__next_data__" in html_lower or "_next/static" in html_lower or "/_next/" in html_lower:
                _set_tech(tech, "framework", "Next.js", "High")
                _set_tech(tech, "language", "JavaScript", "High")
                _detected_js.add("Next.js")
            if "__nuxt" in html_lower or "_nuxt/" in html_lower or "window.__nuxt" in html_lower:
                _set_tech(tech, "framework", "Nuxt", "High")
                _set_tech(tech, "language", "JavaScript", "High")
                _detected_js.add("Nuxt")
            if "ng-version" in html_lower or "ng-app" in html_lower or "angular.min.js" in html_lower or "angular.js" in html_lower:
                _add_js_sig(tech, "Angular", _detected_js)
            if 'data-reactroot' in html_lower or 'data-reactid' in html_lower or 'react-root' in html_lower or 'react.production.min.js' in html_lower or 'react-dom' in html_lower:
                _add_js_sig(tech, "React", _detected_js)
            if 'data-v-' in html_lower or 'vue.min.js' in html_lower or 'vue.js' in html_lower or '__vue__' in html_lower:
                _add_js_sig(tech, "Vue.js", _detected_js)
            if "jquery" in html_lower and ("jquery.min.js" in html_lower or "jquery-" in html_lower or "jquery/" in html_lower):
                _add_js_sig(tech, "jQuery", _detected_js)

            # CSS Frameworks
            if "bootstrap.min.css" in html_lower or "bootstrap.css" in html_lower or "bootstrap/" in html_lower:
                _set_tech(tech, "css_framework", "Bootstrap", "High")
            if "tailwind" in html_lower and ("tailwindcss" in html_lower or "tailwind.min.css" in html_lower):
                _set_tech(tech, "css_framework", "Tailwind CSS", "Medium")

            # Backend framework clues from HTML
            if "x-application-context" in header_keys_lower:
                _set_tech(tech, "framework", "Spring", "High")
                _set_tech(tech, "language", "Java", "High")

            # FastAPI / Swagger docs signature
            content_type_lower = headers.get("Content-Type", "").lower()
            if "x-process-time" in header_keys_lower:
                _set_tech(tech, "language", "Python", "Low")

    except Exception as e:
        logger.warning(f"Failed to perform technology fingerprinting for {url}: {str(e)}")

    _tech_cache[cache_key] = tech
    return tech


def _set_tech(tech: Dict, key: str, value: str, confidence: str) -> None:
    """Set a technology field, preferring higher-confidence detections."""
    CONF_RANK = {"low": 0, "medium": 1, "high": 2}
    current = tech.get(key)
    current_conf = tech["detection_confidence"].get(key, "low")

    if current is None or CONF_RANK.get(confidence.lower(), 0) >= CONF_RANK.get(current_conf.lower(), 0):
        tech[key] = value
        tech["detection_confidence"][key] = confidence


def _add_js_sig(tech: Dict, name: str, detected: set) -> None:
    """Add a JS framework/library to html_signatures, avoiding duplicates."""
    if name not in detected:
        detected.add(name)
        if name not in tech["html_signatures"]:
            tech["html_signatures"].append(name)


# ────────────────────────────────────────────────────────────────────────
# CVSS 3.1 Vector Generation
# ────────────────────────────────────────────────────────────────────────

# Pre-defined CVSS mappings for common vulnerability types
CVSS_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "missing_https_redirect": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "base_score": 6.5,
        "severity": "Medium",
    },
    "deprecated_tls": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score": 7.4,
        "severity": "High",
    },
    "weak_cipher": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score": 5.9,
        "severity": "Medium",
    },
    "expired_cert": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "base_score": 6.5,
        "severity": "Medium",
    },
    "self_signed_cert": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score": 7.4,
        "severity": "High",
    },
    "hostname_mismatch": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score": 7.4,
        "severity": "High",
    },
    "missing_csp": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "base_score": 6.1,
        "severity": "Medium",
    },
    "weak_csp": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "base_score": 6.1,
        "severity": "Medium",
    },
    "missing_hsts": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "base_score": 4.8,
        "severity": "Medium",
    },
    "missing_x_frame_options": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "base_score": 6.1,
        "severity": "Medium",
    },
    "missing_x_content_type": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "base_score": 4.3,
        "severity": "Medium",
    },
    "reflected_xss": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "base_score": 6.1,
        "severity": "Medium",
    },
    "reflected_xss_unescaped": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "base_score": 9.3,
        "severity": "Critical",
    },
    "open_redirect": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "base_score": 6.1,
        "severity": "Medium",
    },
    "cors_wildcard_credentials": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score": 9.1,
        "severity": "Critical",
    },
    "cors_reflected_origin": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        "base_score": 7.1,
        "severity": "High",
    },
    "csrf_missing_token": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "base_score": 6.5,
        "severity": "Medium",
    },
    "insecure_cookie": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "base_score": 5.3,
        "severity": "Medium",
    },
    "exposed_env_file": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "severity": "Critical",
    },
    "exposed_git": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score": 7.5,
        "severity": "High",
    },
    "exposed_backup": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score": 7.5,
        "severity": "High",
    },
    "insecure_port_ftp": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score": 7.5,
        "severity": "High",
    },
    "insecure_port_telnet": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score": 9.1,
        "severity": "Critical",
    },
    "missing_spf": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "base_score": 4.3,
        "severity": "Medium",
    },
    "missing_dmarc": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "base_score": 4.3,
        "severity": "Medium",
    },
    "api_endpoint_exposed": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "base_score": 5.3,
        "severity": "Medium",
    },
}


def get_cvss(vuln_type: str) -> Dict[str, Any]:
    """
    Return CVSS 3.1 data for a known vulnerability type.
    Returns empty dict for informational/non-vulnerability findings.
    """
    return CVSS_MAPPINGS.get(vuln_type, {})


# ────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping
# ────────────────────────────────────────────────────────────────────────

MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "xss": {
        "technique": "Drive-by Compromise",
        "technique_id": "T1189",
        "attack_stage": "Initial Access",
    },
    "open_redirect": {
        "technique": "Phishing: Spearphishing Link",
        "technique_id": "T1566.002",
        "attack_stage": "Initial Access",
    },
    "exposed_credentials": {
        "technique": "Unsecured Credentials: Credentials in Files",
        "technique_id": "T1552.001",
        "attack_stage": "Credential Access",
    },
    "exposed_source_code": {
        "technique": "Unsecured Credentials: Credentials in Files",
        "technique_id": "T1552.001",
        "attack_stage": "Credential Access",
    },
    "csrf": {
        "technique": "Forge Web Credentials",
        "technique_id": "T1606",
        "attack_stage": "Credential Access",
    },
    "cors_misconfiguration": {
        "technique": "Steal Web Session Cookie",
        "technique_id": "T1539",
        "attack_stage": "Credential Access",
    },
    "insecure_cookie": {
        "technique": "Steal Web Session Cookie",
        "technique_id": "T1539",
        "attack_stage": "Credential Access",
    },
    "deprecated_tls": {
        "technique": "Adversary-in-the-Middle",
        "technique_id": "T1557",
        "attack_stage": "Credential Access",
    },
    "missing_https": {
        "technique": "Adversary-in-the-Middle",
        "technique_id": "T1557",
        "attack_stage": "Credential Access",
    },
    "tech_disclosure": {
        "technique": "Gather Victim Host Information: Software",
        "technique_id": "T1592.002",
        "attack_stage": "Reconnaissance",
    },
    "insecure_port": {
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "attack_stage": "Initial Access",
    },
    "api_exposure": {
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "attack_stage": "Initial Access",
    },
    "email_spoofing": {
        "technique": "Phishing",
        "technique_id": "T1566",
        "attack_stage": "Initial Access",
    },
}


def get_mitre_mapping(vuln_type: str) -> Optional[Dict[str, str]]:
    """
    Return MITRE ATT&CK mapping for a vulnerability type.
    Returns None if no meaningful mapping exists.
    """
    return MITRE_MAPPINGS.get(vuln_type)


# ────────────────────────────────────────────────────────────────────────
# Formatting & Utility Functions
# ────────────────────────────────────────────────────────────────────────

def format_description(
    description: str,
    confidence: str = "Medium",
    evidence: str = "N/A",
    http_status: str = "N/A",
    affected_url: str = "N/A",
    scanner_name: str = "N/A",
    detection_method: str = "N/A",
    timestamp: str = None,
    request_method: str = "N/A",
    response_headers: str = "N/A",
    response_snippet: str = "N/A",
    matched_payload: str = "N/A",
    matched_header: str = "N/A",
    owasp_mapping: str = "N/A",
    cwe_mapping: str = "N/A",
    cvss_estimate: str = "N/A",
    references: List[str] = None,
    cvss_vector: str = None,
    mitre_attack: Dict[str, str] = None,
    confidence_score: int = None,
    validation_count: int = None,
    evidence_count: int = None,
    reliability_score: float = None,
    false_positive_probability: float = None,
    verification_method: str = "N/A",
    compliance_mappings: Dict[str, str] = None,
    epss_score: float = None,
) -> str:
    """
    Formulate a comprehensive description string containing all security metrics
    without altering database fields.
    """
    ts = timestamp or datetime_now_utc_str()
    ref_list = references or ["N/A"]
    ref_str = "\n".join(f"  - {ref}" for ref in ref_list)

    # Truncate response snippet if it's too long
    snippet = response_snippet
    if snippet and len(snippet) > 200:
        snippet = snippet[:200] + "..."

    # Truncate response headers if they are too long
    headers_str = response_headers
    if headers_str and len(headers_str) > 200:
        headers_str = headers_str[:200] + "..."

    result = f"""{description}

---
• **Confidence Level:** {confidence}"""

    if confidence_score is not None:
        result += f"\n• **Confidence Score:** {confidence_score}%"
    if validation_count is not None:
        result += f"\n• **Validation Count:** {validation_count}"
    if evidence_count is not None:
        result += f"\n• **Evidence Count:** {evidence_count}"
    if reliability_score is not None:
        result += f"\n• **Reliability Score:** {int(reliability_score * 100)}%"
    if false_positive_probability is not None:
        result += f"\n• **False Positive Probability:** {int(false_positive_probability * 100)}%"

    result += f"""
• **Evidence:** {evidence}
• **HTTP Status:** {http_status}
• **Affected URL:** {affected_url}
• **Scanner Name:** {scanner_name}
• **Detection Method:** {detection_method}
• **Verification Method:** {verification_method}
• **Timestamp:** {ts}
• **Request Method:** {request_method}
• **Response Headers:** {headers_str}
• **Response Snippet:** {snippet}
• **Matched Payload:** {matched_payload}
• **Matched Header:** {matched_header}
• **OWASP Mapping:** {owasp_mapping}
• **CWE Mapping:** {cwe_mapping}
• **CVSS Estimate:** {cvss_estimate}"""

    if cvss_vector:
        result += f"\n• **CVSS Vector:** {cvss_vector}"

    if epss_score is not None:
        result += f"\n• **EPSS Score:** {epss_score}%"

    if mitre_attack:
        result += f"\n• **MITRE ATT&CK:** {mitre_attack.get('technique', 'N/A')} ({mitre_attack.get('technique_id', 'N/A')}) — {mitre_attack.get('attack_stage', 'N/A')}"

    if compliance_mappings:
        compliance_str = ", ".join(f"{k}: {v}" for k, v in compliance_mappings.items())
        result += f"\n• **Compliance Mappings:** {compliance_str}"

    result += f"\n• **References:**\n{ref_str}"
    return result


def datetime_now_utc_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def should_skip_scanner(target: str, scanner_name: str) -> bool:
    """
    Determine if a scanner should be skipped based on target technology.
    """
    tech = get_tech_fingerprint(target)
    
    # 1. Skip PHP-only checks on non-PHP frameworks
    if scanner_name in ("ExposedFilesScanner", "RobotsScanner", "TechDetector"):
        # Let these run generally, but skip specific php/wordpress signatures inside them
        pass

    # WordPress CMS check
    if tech["cms"] != "WordPress":
        # If we have a React / Next.js / Python stack, skip WordPress target checks
        if tech["framework"] in ("Next.js", "Django", "Flask") and scanner_name == "RobotsScanner":
            # Just let it run but exclude wordpress admin paths
            pass
            
    # Language mismatch rules
    lang = tech["language"]
    framework = tech["framework"]
    
    if lang == "PHP" and scanner_name == "SSLScanner":
        # SSL checks should always run
        pass
        
    return False


def parse_vulnerability_description(description: str) -> dict:
    """
    Parse a formatted vulnerability description to retrieve individual security metrics (Phase 1).
    """
    metrics = {
        "confidence_level": "Medium",
        "confidence_score": None,
        "validation_count": None,
        "evidence_count": None,
        "reliability_score": None,
        "false_positive_probability": None,
        "evidence": "N/A",
        "http_status": "N/A",
        "affected_url": "N/A",
        "scanner_name": "N/A",
        "detection_method": "N/A",
        "verification_method": "N/A",
        "timestamp": "N/A",
        "request_method": "GET",
        "response_headers": "N/A",
        "response_snippet": "N/A",
        "matched_payload": "N/A",
        "matched_header": "N/A",
        "owasp_mapping": "N/A",
        "cwe_mapping": "N/A",
        "cvss_estimate": "N/A",
        "cvss_vector": None,
        "epss_score": None,
        "mitre_attack": None,
        "compliance_mappings": {},
        "references": [],
        "description_body": description.split("\n\n---\n")[0] if "\n\n---\n" in description else description
    }
    
    if not description:
        return metrics

    import re
    # Extract line-by-line bullet points
    lines = description.splitlines()
    for line in lines:
        line_strip = line.strip()
        if line_strip.startswith("•"):
            m = re.search(r"• \*\*(.+?):\*\* (.+)", line_strip)
            if m:
                label, val = m.group(1).strip(), m.group(2).strip()
                label_lower = label.lower()
                if label_lower == "confidence level":
                    metrics["confidence_level"] = val
                elif label_lower == "confidence score":
                    metrics["confidence_score"] = int(val.rstrip("%")) if val.rstrip("%").isdigit() else None
                elif label_lower == "validation count":
                    metrics["validation_count"] = int(val) if val.isdigit() else None
                elif label_lower == "evidence count":
                    metrics["evidence_count"] = int(val) if val.isdigit() else None
                elif label_lower == "reliability score":
                    val_clean = val.rstrip("%")
                    metrics["reliability_score"] = float(val_clean) / 100.0 if val_clean.replace(".", "", 1).isdigit() else None
                elif label_lower == "false positive probability":
                    val_clean = val.rstrip("%")
                    metrics["false_positive_probability"] = float(val_clean) / 100.0 if val_clean.replace(".", "", 1).isdigit() else None
                elif label_lower == "evidence":
                    metrics["evidence"] = val
                elif label_lower == "http status":
                    metrics["http_status"] = val
                elif label_lower == "affected url":
                    metrics["affected_url"] = val
                elif label_lower == "scanner name":
                    metrics["scanner_name"] = val
                elif label_lower == "detection method":
                    metrics["detection_method"] = val
                elif label_lower == "verification method":
                    metrics["verification_method"] = val
                elif label_lower == "timestamp":
                    metrics["timestamp"] = val
                elif label_lower == "request method":
                    metrics["request_method"] = val
                elif label_lower == "response headers":
                    metrics["response_headers"] = val
                elif label_lower == "response snippet":
                    metrics["response_snippet"] = val
                elif label_lower == "matched payload":
                    metrics["matched_payload"] = val
                elif label_lower == "matched header":
                    metrics["matched_header"] = val
                elif label_lower == "owasp mapping":
                    metrics["owasp_mapping"] = val
                elif label_lower == "cwe mapping":
                    metrics["cwe_mapping"] = val
                elif label_lower == "cvss estimate":
                    metrics["cvss_estimate"] = val
                elif label_lower == "cvss vector":
                    metrics["cvss_vector"] = val
                elif label_lower == "epss score":
                    metrics["epss_score"] = float(val.rstrip("%")) if val.rstrip("%").replace(".", "", 1).isdigit() else None
                elif label_lower == "mitre att&ck":
                    metrics["mitre_attack"] = val
                elif label_lower == "compliance mappings":
                    # Parse k: v pairs
                    parts = val.split(",")
                    for part in parts:
                        if ":" in part:
                            kp, vp = part.split(":", 1)
                            metrics["compliance_mappings"][kp.strip()] = vp.strip()

    # Extract references list
    ref_started = False
    for line in lines:
        if "• **References:**" in line:
            ref_started = True
            continue
        if ref_started:
            if line.strip().startswith("- "):
                metrics["references"].append(line.strip()[2:])
            elif line.strip().startswith("•"):
                # Hit another bullet, stop
                ref_started = False
            elif line.strip() == "":
                pass

    return metrics
