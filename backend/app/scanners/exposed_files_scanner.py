from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
from urllib.parse import urljoin

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
            sensitive_files = ["/.env", "/.git/config", "/backup.zip", "/config.php", "/.DS_Store"]
            exposed = []

            with SafeHTTPClient(timeout=2.0) as client:
                for file_path in sensitive_files:
                    file_url = urljoin(base_url.rstrip("/") + "/", file_path.lstrip("/"))
                    try:
                        resp = client.get(file_url, follow_redirects=True)
                        if resp.status_code == 200:
                            content = resp.text
                            if len(content) > 0:
                                is_exposed = True
                                if file_path == "/.env" and "DB_" not in content and "APP_" not in content and "SECRET" not in content:
                                    is_exposed = False
                                if file_path == "/.git/config" and "[core]" not in content:
                                    is_exposed = False
                                
                                if is_exposed:
                                    exposed.append(file_path)
                    except Exception:
                        pass
            
            if exposed:
                findings.append({
                    "title": "Exposed Sensitive Files",
                    "severity": "Critical",
                    "description": f"Sensitive system configuration or version control files are publicly accessible: {', '.join(exposed)}.",
                    "recommendation": "Remove public access to these sensitive assets immediately and configure server routing to block .env, .git, and backup file downloads."
                })
                severity = "Critical"
                status = "warning"
            else:
                findings.append({
                    "title": "Sensitive File Probing Clean",
                    "severity": "Informational",
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
