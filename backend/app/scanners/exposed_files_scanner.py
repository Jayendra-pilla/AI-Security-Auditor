from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
import json
from urllib.parse import urljoin
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class ExposedFilesScanner:
    """
    Scanner to detect public exposure of sensitive backup or configuration files.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"ExposedFilesScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            sensitive_files = ["/.env", "/.git/config", "/backup.zip", "/composer.json", "/package.json", "/robots.txt.bak"]
            exposed = []
            evidence_data = {}

            with SafeHTTPClient(timeout=2.0) as client:
                for file_path in sensitive_files:
                    file_url = urljoin(base_url.rstrip("/") + "/", file_path.lstrip("/"))
                    try:
                        resp = client.get(file_url, follow_redirects=True)
                        if resp.status_code == 200:
                            content = resp.text
                            content_bytes = resp.content
                            is_exposed = False
                            
                            if file_path == "/.env":
                                if any(k in content for k in ("DB_", "APP_", "SECRET", "JWT_", "PASSWORD", "KEY")):
                                    is_exposed = True
                            elif file_path == "/.git/config":
                                if "[core]" in content or "[repositoryformatversion]" in content:
                                    is_exposed = True
                            elif file_path == "/backup.zip":
                                ct = resp.headers.get("Content-Type", "").lower()
                                if len(content_bytes) > 0 and ("zip" in ct or "octet-stream" in ct):
                                    is_exposed = True
                            elif file_path in ("/composer.json", "/package.json"):
                                try:
                                    parsed = json.loads(content)
                                    if "dependencies" in parsed or "require" in parsed or "name" in parsed:
                                        is_exposed = True
                                except Exception:
                                    pass
                            elif file_path == "/robots.txt.bak":
                                if "user-agent:" in content.lower() or "disallow:" in content.lower():
                                    is_exposed = True

                            if is_exposed:
                                exposed.append(file_path)
                                evidence_data[file_path] = {
                                    "status_code": resp.status_code,
                                    "content_length": len(content_bytes),
                                    "content_type": resp.headers.get("Content-Type")
                                }
                    except Exception as req_err:
                        logger.debug(f"Exposed file query fail on {file_path}: {str(req_err)}")
            
            if exposed:
                # Assess severity dynamically
                has_critical = any(f in exposed for f in ("/.env", "/.git/config"))
                has_high = any(f in exposed for f in ("/backup.zip",))
                
                vuln_sev = "Critical" if has_critical else ("High" if has_high else "Medium")
                cwe_val = "CWE-538" if has_critical else "CWE-200"

                # Get CVSS details
                vuln_type = "exposed_env_file" if has_critical else ("exposed_git" if "/.git/config" in exposed else "exposed_backup")
                cvss = get_cvss(vuln_type)
                mitre = get_mitre_mapping("exposed_credentials" if has_critical else "exposed_source_code")

                conf = calculate_confidence(
                    validation_methods=["File Content Verification", "Response Code Validation"],
                    evidence_quality="high",
                    multiple_confirmations=len(exposed),
                )

                findings.append({
                    "title": "Exposed Sensitive Files",
                    "severity": vuln_sev,
                    "confidence": conf["confidence"],
                    "evidence": f"Exposed files verified: {exposed}. Metadata: {evidence_data}",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "ExposedFilesScanner",
                    "detection_method": "File Content Verification Probe",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": cwe_val,
                    "cvss_estimate": str(cvss.get("base_score", "7.5")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    "description": f"Sensitive system configuration, backup, or version control files are publicly accessible: {', '.join(exposed)}.",
                    "recommendation": "Remove public access to these sensitive assets immediately and configure server routing to block .env, .git, and backup file downloads."
                })
                severity = vuln_sev
                status = "warning"
            else:
                findings.append({
                    "title": "Sensitive File Probing Clean",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Probed configuration files (.env, .git/config, backup.zip, composer.json, package.json, robots.txt.bak). No public exposures confirmed.",
                    "http_status": 200,
                    "affected_url": base_url,
                    "scanner_name": "ExposedFilesScanner",
                    "detection_method": "File Content Verification Probe",
                    "timestamp": datetime_now_utc_str(),
                    "description": "Checked common configuration directories and file routes. No public exposure discovered.",
                    "recommendation": "Set up server directory policies to prohibit access to system files."
                })
        except Exception as e:
            logger.error(f"ExposedFilesScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "File Exposure Probe Failure",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": target,
                "scanner_name": "ExposedFilesScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Failed to perform sensitive file checking. Error: {str(e)}",
                "recommendation": "Audit web root folders manually to search for backup or source control structures."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"ExposedFilesScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "ExposedFilesScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
