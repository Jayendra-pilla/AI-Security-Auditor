from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from urllib.parse import urljoin
from app.scanners.scanner_utils import datetime_now_utc_str
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class RobotsScanner:
    """
    Scanner to detect and inspect robots.txt configurations for sensitive path exposures.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"RobotsScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
            
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(robots_url, follow_redirects=True)
            
            if resp.status_code == 200:
                content = resp.text
                
                # Classifications by severity tier
                high_severity_paths = []   # .git, .env, .svn, .htaccess, .htpasswd
                admin_paths = []           # admin panels → Medium
                backup_paths = []          # backups, dumps → Medium
                config_paths = []          # config files → Medium
                private_paths = []         # internal, private, source, deploy → Low
                informational_paths = []   # login, signup, register, api, graphql → Informational

                for line in content.splitlines():
                    line_strip = line.strip()
                    if line_strip.lower().startswith("disallow"):
                        parts = line_strip.split(":", 1)
                        if len(parts) > 1:
                            path = parts[1].strip()
                            path_lower = path.lower()
                            if not path or path == "/":
                                continue

                            # 0. High severity: version control, env files, server config
                            if any(k in path_lower for k in (".git", ".env", ".svn", ".htaccess", ".htpasswd", ".DS_Store")):
                                high_severity_paths.append(path)
                            # 1. Informational: ordinary login, signup, register, api, graphql, rss, feed, sitemap
                            elif any(k in path_lower for k in ("login", "signin", "auth", "logout", "signup", "register", "api", "graphql", "rss", "feed", "sitemap")):
                                informational_paths.append(path)
                            # 2. Admin
                            elif any(k in path_lower for k in ("admin", "administrator", "wp-admin", "cpanel", "control")):
                                admin_paths.append(path)
                            # 3. Backup
                            elif any(k in path_lower for k in ("backup", "backups", "bak", "dump", "archive", "zip", "tar", "gz", "sql")):
                                backup_paths.append(path)
                            # 4. Config
                            elif any(k in path_lower for k in ("config", "configuration", "settings", "conf", "properties", "ini", "xml")):
                                config_paths.append(path)
                            # 5. Private/Internal/Source/Deploy
                            elif any(k in path_lower for k in ("private", "secret", "internal", "src", "source", "db", "database", "deploy", "deployment")):
                                private_paths.append(path)

                sensitive_exposures = []
                max_vuln_sev = "Informational"

                if high_severity_paths:
                    sensitive_exposures.append(f"Critical/High Security Files: {high_severity_paths}")
                    max_vuln_sev = "High"
                if admin_paths:
                    sensitive_exposures.append(f"Admin: {admin_paths}")
                    if max_vuln_sev not in ("High", "Critical"):
                        max_vuln_sev = "Medium"
                if backup_paths:
                    sensitive_exposures.append(f"Backup: {backup_paths}")
                    if max_vuln_sev not in ("High", "Critical"):
                        max_vuln_sev = "Medium"
                if config_paths:
                    sensitive_exposures.append(f"Config: {config_paths}")
                    if max_vuln_sev not in ("High", "Critical"):
                        max_vuln_sev = "Medium"
                if private_paths:
                    sensitive_exposures.append(f"Private/Internal/Source/Deploy: {private_paths}")
                    if max_vuln_sev not in ("High", "Critical", "Medium"):
                        max_vuln_sev = "Low"

                # Report findings based on classifications
                if sensitive_exposures:
                    conf = calculate_confidence(
                        validation_methods=["Content Validation"],
                        evidence_quality="high",
                    )
                    findings.append({
                        "title": "Sensitive Path Exposure in robots.txt",
                        "severity": max_vuln_sev,
                        "confidence": conf["confidence"],
                        "evidence": f"Sensitive disallowed paths found: {'; '.join(sensitive_exposures)}",
                        "http_status": resp.status_code,
                        "affected_url": robots_url,
                        "scanner_name": "RobotsScanner",
                        "detection_method": "robots.txt Parsing",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": "GET",
                        "response_headers": str(dict(resp.headers)),
                        "response_snippet": content[:200],
                        "matched_payload": "N/A",
                        "matched_header": "N/A",
                        "owasp_mapping": "A05:2021-Security Misconfiguration",
                        "cwe_mapping": "CWE-538",
                        "references": ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Review_Webserver_Metafiles_for_Information_Leakage"],
                        "description": f"Robots.txt discloses sensitive administrator, backup, config, or internal paths: {'; '.join(sensitive_exposures)}.",
                        "recommendation": "Do not list private folders or backup files in robots.txt. Enforce authorization controls on those folders instead."
                    })
                    severity = max_vuln_sev
                    status = "warning"
                
                # Ordinary login pages / non-sensitive mappings logged as informational
                if informational_paths:
                    conf = calculate_confidence(
                        validation_methods=["Content Validation"],
                        evidence_quality="high",
                    )
                    findings.append({
                        "title": "Robots.txt Discovered (Informational Mappings)",
                        "severity": "Informational",
                        "confidence": conf["confidence"],
                        "evidence": f"Informational paths listed: {informational_paths}",
                        "http_status": resp.status_code,
                        "affected_url": robots_url,
                        "scanner_name": "RobotsScanner",
                        "detection_method": "robots.txt Parsing",
                        "timestamp": datetime_now_utc_str(),
                        "description": f"Robots.txt is present and lists standard informational routes: {informational_paths}.",
                        "recommendation": "Informational routes (like login, signup, register, API endpoints) listed in robots.txt do not represent high-risk exposures."
                    })
                
                # If no paths at all or no sensitive/informational paths found
                if not sensitive_exposures and not informational_paths:
                    findings.append({
                        "title": "Robots.txt Clean",
                        "severity": "Informational",
                        "confidence": "High",
                        "evidence": "Robots.txt was resolved but contained no sensitive path disclosures.",
                        "http_status": resp.status_code,
                        "affected_url": robots_url,
                        "scanner_name": "RobotsScanner",
                        "detection_method": "robots.txt Parsing",
                        "timestamp": datetime_now_utc_str(),
                        "description": "Robots.txt file does not disclose any known sensitive application structures.",
                        "recommendation": "Regularly audit robots.txt disclosures."
                    })
            else:
                findings.append({
                    "title": "Robots.txt Not Found",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"HTTP status code {resp.status_code}",
                    "http_status": resp.status_code,
                    "affected_url": robots_url,
                    "scanner_name": "RobotsScanner",
                    "detection_method": "robots.txt Check",
                    "timestamp": datetime_now_utc_str(),
                    "description": f"Robots.txt could not be resolved (HTTP {resp.status_code}).",
                    "recommendation": "Deploy a robots.txt file to guide search engine crawlers if required."
                })
        except Exception as e:
            logger.error(f"RobotsScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Robots.txt Scan Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": robots_url,
                "scanner_name": "RobotsScanner",
                "detection_method": "Connection attempt",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not scan robots.txt on {target}. Error: {str(e)}",
                "recommendation": "Verify target accessibility and inspect robots.txt manually."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"RobotsScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "RobotsScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
