import socket
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class PortScanner:
    """
    Scanner to identify open service ports on the target host.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"PortScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            if target.startswith(("http://", "https://")):
                host = urlparse(target).hostname or ""
            else:
                host = target.split("/")[0]
            if not host:
                host = target

            common_ports = [21, 22, 23, 25, 80, 443, 8080]
            open_ports = []
            
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.2)
                        result = s.connect_ex((host, port))
                        if result == 0:
                            open_ports.append(port)
                except Exception:
                    pass
            
            if open_ports:
                for port in open_ports:
                    if port in [21, 23]:
                        findings.append({
                            "title": f"Insecure Service Port Open: {port}",
                            "severity": "High",
                            "description": f"Unencrypted service port {port} (FTP/Telnet) is open on {host}.",
                            "recommendation": "Close insecure service ports and use secure alternatives like SSH (22)."
                        })
                        severity = "High"
                        status = "warning"
                    else:
                        findings.append({
                            "title": f"Port {port} is Open",
                            "severity": "Informational",
                            "description": f"Standard port {port} is open and accepting connections on {host}.",
                            "recommendation": "Ensure only necessary ports are exposed to the public internet."
                        })
            else:
                findings.append({
                    "title": "Port Scan Clean",
                    "severity": "Informational",
                    "description": f"No common service ports were detected open on the host {host}.",
                    "recommendation": "Regularly run port vulnerability scans."
                })
        except Exception as e:
            logger.error(f"PortScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Port Probe Failed",
                "severity": "Low",
                "description": f"Failed to perform port scanning on {target}. Error: {str(e)}",
                "recommendation": "Check target domain validity and access configurations."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"PortScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "PortScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
