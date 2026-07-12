import logging
from typing import Dict, Any, List, Type

# Import all individual scanner classes
from app.scanners.header_scanner import HeaderScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.cors_scanner import CORSScanner
from app.scanners.cookie_scanner import CookieScanner
from app.scanners.csrf_scanner import CSRFScanner
from app.scanners.dns_scanner import DNSScanner 
from app.scanners.port_scanner import PortScanner
from app.scanners.robots_scanner import RobotsScanner
from app.scanners.sitemap_scanner import SitemapScanner
from app.scanners.subdomain_scanner import SubdomainScanner
from app.scanners.tech_detector import TechDetector
from app.scanners.xss_scanner import XSSScanner
from app.scanners.clickjacking_scanner import ClickjackingScanner
from app.scanners.open_redirect_scanner import OpenRedirectScanner
from app.scanners.api_endpoint_scanner import APIEndpointScanner
from app.scanners.exposed_files_scanner import ExposedFilesScanner
from app.observability.metrics import MetricsService

# Setup logger
logger = logging.getLogger(__name__)
metrics = MetricsService()

class ScannerManager:
    """
    ScannerManager acts as the central orchestrator to run all security scanners.
    It provides a unified entry point to execute scanners sequentially,
    collect and normalize results, and gracefully handle scanner failures.
    """

    def __init__(self) -> None:
        # Define the ordered list of all security scanners
        self.scanners: List[Type[Any]] = [
            HeaderScanner,
            SSLScanner,
            CORSScanner,
            CookieScanner,
            CSRFScanner,
            DNSScanner,
            PortScanner,
            RobotsScanner,
            SitemapScanner,
            SubdomainScanner,
            TechDetector,
            XSSScanner,
            ClickjackingScanner,
            OpenRedirectScanner,
            APIEndpointScanner,
            ExposedFilesScanner,
        ]

    def run_all_scanners(self, target: str) -> Dict[str, Any]:
        """
        Executes all registered scanners against the target target.
        If any scanner fails or is not implemented, the remaining scanners
        will continue execution.

        Args:
            target: The target host, IP, or URL to be scanned.

        Returns:
            A normalized dictionary containing the overall scan status, target,
            counts of executed scanners, and the individual scanner results.
        """
        results: List[Dict[str, Any]] = []
        completed_scanners = 0
        total_scanners = len(self.scanners)

        for scanner_class in self.scanners:
            scanner_name = scanner_class.__name__
            logger.info(f"Starting scanner: {scanner_name}")
            
            try:
                # Instantiate the scanner
                scanner_instance = scanner_class()
                
                # Check for standard methods 'scan' or 'run'
                if hasattr(scanner_instance, "scan") and callable(getattr(scanner_instance, "scan")):
                    findings = scanner_instance.scan(target)
                elif hasattr(scanner_instance, "run") and callable(getattr(scanner_instance, "run")):
                    findings = scanner_instance.run(target)
                else:
                    # Provide helpful context for placeholders or unimplemented scanners
                    raise NotImplementedError(
                        f"Scanner class '{scanner_name}' does not implement a callable 'scan' or 'run' method."
                    )
                
                if isinstance(findings, dict) and "scanner" in findings and "status" in findings and "findings" in findings:
                    results.append(findings)
                else:
                    results.append({
                        "scanner": scanner_name,
                        "status": "success",
                        "findings": findings
                    })
                completed_scanners += 1
                logger.info(f"Finished scanner: {scanner_name}")
                
                # Record per-scanner duration to metrics
                if isinstance(findings, dict):
                    dur = findings.get("duration_ms")
                elif isinstance(results[-1], dict):
                    dur = results[-1].get("duration_ms")
                else:
                    dur = None
                if dur is not None:
                    metrics.record_scanner(scanner_name, float(dur))
                
            except Exception as e:
                logger.error(f"Failed scanner: {scanner_name}. Error: {str(e)}")
                results.append({
                    "scanner": scanner_name,
                    "status": "failed",
                    "error": str(e)
                })

        return {
            "target": target,
            "status": "completed",
            "total_scanners": total_scanners,
            "completed_scanners": completed_scanners,
            "results": results
        }
