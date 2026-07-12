import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Severity ranking for comparison (higher index = more severe)
SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _max_severity(current: str, candidate: str) -> str:
    """Return the more severe of two severity strings."""
    if SEVERITY_RANK.get(candidate.lower(), 0) > SEVERITY_RANK.get(current.lower(), 0):
        return candidate
    return current


def _extract_scanner(results: Dict[str, Any], scanner_name: str) -> Dict[str, Any]:
    """
    Extract a single scanner's result block from the ScannerManager results dict.
    Returns a normalized dict with 'status' and 'findings' keys.
    """
    for entry in results.get("results", []):
        if entry.get("scanner") == scanner_name:
            return {
                "status": entry.get("status", "unknown"),
                "findings": entry.get("findings", []),
            }
    return {"status": "not_found", "findings": []}


class ReconAgent:
    """
    Reconnaissance intelligence agent.
    Aggregates outputs from DNSScanner, RobotsScanner, SitemapScanner,
    and SubdomainScanner into a unified domain-level report.
    """

    SCANNER_MAP = {
        "dns": "DNSScanner",
        "robots": "RobotsScanner",
        "sitemap": "SitemapScanner",
        "subdomains": "SubdomainScanner",
    }

    def analyze(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scanner results and produce a structured reconnaissance report.

        Args:
            results: The full dict returned by ScannerManager.run_all_scanners().

        Returns:
            A dictionary containing aggregated reconnaissance intelligence.
        """
        logger.info("ReconAgent analysis started.")

        report: Dict[str, Any] = {}
        max_sev = "Informational"
        total_findings = 0
        scanner_count = 0

        for domain_key, scanner_name in self.SCANNER_MAP.items():
            extracted = _extract_scanner(results, scanner_name)
            report[domain_key] = extracted
            scanner_count += 1

            findings: List[Dict[str, Any]] = extracted.get("findings", [])
            total_findings += len(findings)

            for finding in findings:
                sev = finding.get("severity", "Informational")
                max_sev = _max_severity(max_sev, sev)

        summary = (
            f"Reconnaissance analysis completed. "
            f"{scanner_count} scanners executed, "
            f"{total_findings} findings detected."
        )

        report.update({
            "agent": "ReconAgent",
            "summary": summary,
            "max_severity": max_sev,
            "scanner_count": scanner_count,
            "finding_count": total_findings,
        })

        logger.info(f"ReconAgent analysis completed: {max_sev} severity, {total_findings} findings.")
        return report
