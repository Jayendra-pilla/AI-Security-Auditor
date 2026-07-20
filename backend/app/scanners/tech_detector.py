import time
import logging
import re
from app.scanners.scanner_utils import get_tech_fingerprint, datetime_now_utc_str
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class TechDetector:
    """
    Scanner to identify technologies, backend frameworks, CMS, CDN, and WAF disclosures.
    Avoids duplicates and returns confidence for every detected technology.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"TechDetector starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            tech = get_tech_fingerprint(target)
            
            disclosures = []
            confidences = tech.get("detection_confidence", {})

            # Map the confidence scores
            def get_conf_desc(key_name, display_name):
                val = tech.get(key_name)
                if val:
                    conf = confidences.get(key_name, "Medium")
                    return f"{display_name}: {val} (Confidence: {conf})"
                return None

            desc_items = []
            
            server_desc = get_conf_desc("web_server", "Web Server")
            if server_desc:
                desc_items.append(server_desc)
                disclosures.append(server_desc)

            framework_desc = get_conf_desc("framework", "Framework")
            if framework_desc:
                desc_items.append(framework_desc)
                disclosures.append(framework_desc)

            lang_desc = get_conf_desc("language", "Programming Language")
            if lang_desc:
                desc_items.append(lang_desc)
                disclosures.append(lang_desc)

            cms_desc = get_conf_desc("cms", "CMS")
            if cms_desc:
                desc_items.append(cms_desc)
                disclosures.append(cms_desc)

            waf_desc = get_conf_desc("waf", "WAF")
            if waf_desc:
                desc_items.append(waf_desc)
                disclosures.append(waf_desc)

            cdn_desc = get_conf_desc("cdn", "CDN")
            if cdn_desc:
                desc_items.append(cdn_desc)
                disclosures.append(cdn_desc)

            cloud_desc = get_conf_desc("cloud_provider", "Cloud Provider")
            if cloud_desc:
                desc_items.append(cloud_desc)
                disclosures.append(cloud_desc)

            css_desc = get_conf_desc("css_framework", "CSS Framework")
            if css_desc:
                desc_items.append(css_desc)
                disclosures.append(css_desc)

            if tech["html_signatures"]:
                sig_items = [f"{sig} (Confidence: High)" for sig in tech["html_signatures"]]
                desc_items.append(f"Frontend Signatures: {', '.join(sig_items)}")
                disclosures.extend(sig_items)

            if disclosures:
                unique_disclosures = sorted(list(set(disclosures)))
                server_val = tech["raw_headers"].get("Server", "")
                powered_val = tech["raw_headers"].get("X-Powered-By", "")
                
                evidence_text = f"Detected stack: {', '.join(unique_disclosures)}. Server header: '{server_val}', X-Powered-By: '{powered_val}'"
                
                # Check for version numbers leak in Server or X-Powered-By header
                has_leak = False
                if re.search(r'\d', server_val) or re.search(r'\d', powered_val):
                    has_leak = True

                findings.append({
                    "title": "Technology and Signature Disclosures" if has_leak else "Technology Signatures Detected",
                    "severity": "Low" if has_leak else "Informational",
                    "confidence": "High",  # Tech detection itself has high confirmation from headers/signatures
                    "evidence": evidence_text,
                    "http_status": 200,
                    "affected_url": target,
                    "scanner_name": "TechDetector",
                    "detection_method": "Header and HTML Fingerprinting",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(tech["raw_headers"])[:200],
                    "matched_payload": "N/A",
                    "matched_header": "Server / X-Powered-By",
                    # No CVSS generated for Tech Detection as per requirements (Phase 7)
                    "cvss_estimate": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-200",
                    "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    "description": f"The target exposes details about its runtime stack: {', '.join(unique_disclosures)}.",
                    "recommendation": "Strip version numbers from Server and X-Powered-By headers, disable X-Powered-By completely, and obscure generator metadata."
                })
                if has_leak:
                    severity = "Low"
                    status = "warning"
            else:
                findings.append({
                    "title": "Technology Disclosures Clean",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "No diagnostic technology signature headers or generator tags resolved.",
                    "http_status": 200,
                    "affected_url": target,
                    "scanner_name": "TechDetector",
                    "detection_method": "Header and HTML Fingerprinting",
                    "timestamp": datetime_now_utc_str(),
                    "description": "No technology headers (Server, X-Powered-By) or framework generator files leaked details.",
                    "recommendation": "Continue following configuration hardening practices."
                })
        except Exception as e:
            logger.error(f"TechDetector error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Technology Signature Probe Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": target,
                "scanner_name": "TechDetector",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform technology detection on {target}. Error: {str(e)}",
                "recommendation": "Inspect HTTP headers manually using command-line tools like curl."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"TechDetector finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "TechDetector",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
