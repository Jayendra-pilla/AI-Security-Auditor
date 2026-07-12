import logging
from typing import List, Dict, Any
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class ReportAgent:
    """
    ReportAgent maps the assessed risk score to a letter grade and compiles
    the final report data structure containing statistics and recommendations.
    """

    def generate_report(
        self,
        risk_score: int,
        summary: str,
        vulnerabilities: List[Vulnerability],
        recommendations: List[str]
    ) -> Dict[str, Any]:
        """
        Compiles the final report object with grade mapping and statistics.

        Args:
            risk_score: Assessed risk score (0-100).
            summary: Brief summary of findings.
            vulnerabilities: List of Vulnerability models.
            recommendations: List of recommendation strings.

        Returns:
            A dictionary matching the required final report structure.
        """
        # Count findings by severity for statistics
        statistics = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        for vuln in vulnerabilities:
            sev = vuln.severity.lower()
            if sev in statistics:
                statistics[sev] += 1
            else:
                statistics["informational"] += 1

        # Map risk score to letter grade (lower risk = better grade)
        if risk_score <= 10:
            grade = "A"
        elif risk_score <= 30:
            grade = "B"
        elif risk_score <= 50:
            grade = "C"
        elif risk_score <= 70:
            grade = "D"
        else:
            grade = "F"

        logger.info(f"Report Agent compiled report with risk_score={risk_score}, grade={grade}.")

        return {
            "risk_score": float(risk_score),
            "grade": grade,
            "summary": summary,
            "statistics": statistics,
            "recommendations": recommendations
        }
