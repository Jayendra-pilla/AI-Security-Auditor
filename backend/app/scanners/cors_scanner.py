from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging

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
            with SafeHTTPClient(timeout=2.0) as client:
                resp = client.get(url, headers={"Origin": "https://attacker.com"}, follow_redirects=True)
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or acao == "https://attacker.com":
                findings.append({
                    "title": "Permissive CORS Policy",
                    "severity": "High",
                    "description": "Access-Control-Allow-Origin is set to wildcards or dynamically echoes unauthorized Origin headers.",
                    "recommendation": "Configure Access-Control-Allow-Origin to authorized origins only."
                })
                severity = "High"
                status = "warning"
        except Exception as e:
            logger.error(f"CORSScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "CORS Check Failed",
                "severity": "Low",
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
