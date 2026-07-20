import socket
import time
import logging
import errno
from urllib.parse import urlparse
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import calculate_confidence

logger = logging.getLogger(__name__)

class PortScanner:
    """
    Scanner to identify open service ports on the target host (A, AAAA).
    Classifies ports as Open, Closed, or Filtered.
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
            closed_ports = []
            filtered_ports = []
            
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.2)
                        result = s.connect_ex((host, port))
                        
                        if result == 0:
                            open_ports.append(port)
                        elif result in (errno.ECONNREFUSED, 10061):
                            closed_ports.append(port)
                        else:
                            filtered_ports.append(port)
                except socket.timeout:
                    filtered_ports.append(port)
                except Exception:
                    filtered_ports.append(port)
            
            if open_ports:
                for port in open_ports:
                    if port in [21, 23]:
                        vuln_type = "insecure_port_ftp" if port == 21 else "insecure_port_telnet"
                        cvss = get_cvss(vuln_type)
                        mitre = get_mitre_mapping("insecure_port")
                        conf = calculate_confidence(
                            validation_methods=["Port Connection Verification"],
                            evidence_quality="high",
                        )
                        findings.append({
                            "title": f"Insecure Service Port Open: {port}",
                            "severity": "High",
                            "confidence": conf["confidence"],
                            "evidence": f"Port: {port}, Connection Status: Open (0)",
                            "http_status": "N/A",
                            "affected_url": f"{host}:{port}",
                            "scanner_name": "PortScanner",
                            "detection_method": "Socket Connection Probe",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": "CONNECT",
                            "owasp_mapping": "A05:2021-Security Misconfiguration",
                            "cwe_mapping": "CWE-693",
                            "cvss_estimate": str(cvss.get("base_score", "7.5")),
                            "cvss_vector": cvss.get("vector", ""),
                            "mitre_attack": mitre,
                            "references": ["https://cwe.mitre.org/data/definitions/693.html"],
                            "description": f"Unencrypted service port {port} (FTP/Telnet) is open and accepting connection handshakes on {host}.",
                            "recommendation": "Close insecure service ports immediately. Use encrypted alternatives like SFTP (SSH/22) or HTTPS (443)."
                        })
                        severity = "High"
                        status = "warning"
                    else:
                        conf = calculate_confidence(
                            validation_methods=["Port Connection Verification"],
                            evidence_quality="high",
                        )
                        findings.append({
                            "title": f"Active Service Port Open: {port}",
                            "severity": "Informational",
                            "confidence": conf["confidence"],
                            "evidence": f"Port: {port}, Connection Status: Open (0)",
                            "http_status": "N/A",
                            "affected_url": f"{host}:{port}",
                            "scanner_name": "PortScanner",
                            "detection_method": "Socket Connection Probe",
                            "timestamp": datetime_now_utc_str(),
                            "request_method": "CONNECT",
                            # Informational finding, no CVSS vector as per Phase 7
                            "description": f"Standard service port {port} is open and accepting connections on {host}.",
                            "recommendation": "Ensure this service is intended to be publicly exposed."
                        })
            
            summary_desc = (
                f"Completed port reconnaissance for {host}. "
                f"Open: {open_ports or 'None'}. "
                f"Closed: {len(closed_ports)} ports. "
                f"Filtered/Blocked: {len(filtered_ports)} ports."
            )
            findings.append({
                "title": "Port Scanning Activity Log",
                "severity": "Informational",
                "confidence": "High",
                "evidence": f"Open: {open_ports}, Closed count: {len(closed_ports)}, Filtered count: {len(filtered_ports)}",
                "http_status": "N/A",
                "affected_url": host,
                "scanner_name": "PortScanner",
                "detection_method": "Socket Probing Sequence",
                "timestamp": datetime_now_utc_str(),
                "description": summary_desc,
                "recommendation": "Maintain a regular port scanning policy to prevent dynamic port leaks."
            })

        except Exception as e:
            logger.error(f"PortScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "Port Probe Failed",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": target,
                "scanner_name": "PortScanner",
                "detection_method": "Socket Connection attempt",
                "timestamp": datetime_now_utc_str(),
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
