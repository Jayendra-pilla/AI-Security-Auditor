import logging
from typing import Dict, Any, List
from app.agents.recon_agent import _max_severity, _extract_scanner

logger = logging.getLogger(__name__)


class TechAgent:
    """
    Technology and exposure intelligence agent.
    Aggregates outputs from TechDetector and ExposedFilesScanner into a unified
    domain-level report covering technology stack disclosures and sensitive file exposures.
    """

    SCANNER_MAP = {
        "tech_detection": "TechDetector",
        "exposed_files": "ExposedFilesScanner",
    }

    def analyze(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scanner results and produce a structured technology report.

        Args:
            results: The full dict returned by ScannerManager.run_all_scanners().

        Returns:
            A dictionary containing aggregated technology and file exposure intelligence.
        """
        logger.info("TechAgent analysis started.")

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
            f"Technology analysis completed. "
            f"{scanner_count} scanners executed, "
            f"{total_findings} findings detected."
        )

        report.update({
            "agent": "TechAgent",
            "summary": summary,
            "max_severity": max_sev,
            "scanner_count": scanner_count,
            "finding_count": total_findings,
        })

        logger.info(f"TechAgent analysis completed: {max_sev} severity, {total_findings} findings.")
        return report
