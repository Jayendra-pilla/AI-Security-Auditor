import json
from datetime import datetime, timezone
from app.models.scan import Scan
from app.models.report import Report

class JSONExportGenerator:
    """
    JSON raw data exporter utility.
    """

    @staticmethod
    def generate(scan: Scan, report: Report) -> str:
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

        vulnerabilities_list = []
        for vuln in scan.vulnerabilities:
            vulnerabilities_list.append({
                "title": vuln.title,
                "severity": vuln.severity,
                "description": vuln.description,
                "recommendation": vuln.recommendation
            })

        export_data = {
            "executive_summary": report.summary,
            "target_url": scan.target,
            "scan_id": scan.scan_id,
            "scan_date": scan_date_str,
            "status": scan.status,
            "risk_score": report.risk_score,
            "security_grade": report.grade,
            "statistics": {
                "total_vulnerabilities": len(scan.vulnerabilities),
                "severity_distribution": severity_distribution
            },
            "vulnerabilities": vulnerabilities_list,
            "ai_recommendations": report.recommendations or [],
            "generated_timestamp": generated_date_str
        }

        return json.dumps(export_data, indent=2)

# Keep the original placeholder class name as an alias for compatibility
JSONReportExporter = JSONExportGenerator

