import json
from datetime import datetime, timezone
from app.models.scan import Scan
from app.models.report import Report
from app.scanners.scanner_utils import parse_vulnerability_description

class JSONExportGenerator:
    """
    JSON raw data exporter utility.
    Supports both 'technical' and 'executive' modes.
    Adds parsed technical metrics to the vulnerability list.
    """

    @staticmethod
    def generate(scan: Scan, report: Report, mode: str = "technical") -> str:
        """
        Serializes scan and report details into a structured JSON string.
        """
        scan_date_str = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        generated_date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        stats = report.statistics or {}
        severity_distribution = {
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
            "informational": stats.get("informational", 0)
        }

        # Filter vulnerabilities by mode
        if mode == "executive":
            vulnerabilities = [
                v for v in scan.vulnerabilities 
                if v.severity.lower() in ("critical", "high", "medium")
            ]
        else:
            vulnerabilities = scan.vulnerabilities

        vulnerabilities_list = []
        for idx, vuln in enumerate(vulnerabilities):
            desc_text = vuln.description or "No description provided."
            parsed = parse_vulnerability_description(desc_text)
            
            if mode == "executive":
                desc_clean = parsed.get("description_body", desc_text).strip()
            else:
                desc_clean = desc_text

            vulnerabilities_list.append({
                "finding_id": f"ASE-{1000 + idx}",
                "title": vuln.title,
                "severity": vuln.severity,
                "description": desc_clean,
                "recommendation": vuln.recommendation,
                "confidence_level": parsed.get("confidence_level"),
                "confidence_score": parsed.get("confidence_score"),
                "reliability_score": parsed.get("reliability_score"),
                "false_positive_probability": parsed.get("false_positive_probability"),
                "cwe_mapping": parsed.get("cwe_mapping"),
                "owasp_mapping": parsed.get("owasp_mapping"),
                "cvss_estimate": parsed.get("cvss_estimate"),
                "cvss_vector": parsed.get("cvss_vector"),
                "validation_count": parsed.get("validation_count"),
                "detection_method": parsed.get("detection_method"),
                "verification_method": parsed.get("verification_method"),
                "affected_url": parsed.get("affected_url")
            })

        # Compliance percentages
        pci_compliance = max(30, min(100, 100 - (stats.get("critical", 0) * 20 + stats.get("high", 0) * 10)))
        iso_compliance = max(40, min(100, 100 - (stats.get("critical", 0) * 15 + stats.get("high", 0) * 8)))

        export_data = {
            "executive_summary": report.summary,
            "target_url": scan.target,
            "scan_id": scan.scan_id,
            "scan_date": scan_date_str,
            "status": scan.status,
            "risk_score": report.risk_score,
            "security_grade": report.grade,
            "compliance": {
                "pci_dss_score": pci_compliance,
                "iso_27001_score": iso_compliance
            },
            "statistics": {
                "total_vulnerabilities": len(scan.vulnerabilities),
                "severity_distribution": severity_distribution
            },
            "vulnerabilities": vulnerabilities_list,
            "ai_recommendations": report.recommendations or [],
            "generated_timestamp": generated_date_str,
            "mode": mode
        }

        return json.dumps(export_data, indent=2)

# Keep the original placeholder class name as an alias for compatibility
JSONReportExporter = JSONExportGenerator
