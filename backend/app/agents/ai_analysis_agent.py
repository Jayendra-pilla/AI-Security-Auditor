import logging
from typing import List, Dict, Any, Optional
from app.models.vulnerability import Vulnerability
from app.ai.gemini import GeminiClient

logger = logging.getLogger(__name__)

class AIAnalysisAgent:
    """
    AI Analysis Agent groups vulnerabilities, constructs a prompt,
    invokes GeminiClient, and returns a normalized dictionary.
    Includes robust fallback logic in case of API keys missing, timeout, or errors.
    """

    def __init__(self, gemini_client: Optional[GeminiClient] = None) -> None:
        self.gemini_client = gemini_client or GeminiClient()

    def analyze(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """
        Runs AI analysis on the scan vulnerabilities. If Gemini fails, runs
        local analysis fallback.

        Returns:
            A normalized dictionary:
            {
                "summary": "...",
                "risk_score": 84,
                "overall_severity": "High",
                "is_fallback": bool
            }
        """
        # 1. Count findings by severity
        stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        findings_summary = []
        for vuln in vulnerabilities:
            sev = vuln.severity.lower()
            if sev in stats:
                stats[sev] += 1
            else:
                stats["informational"] += 1
            findings_summary.append(
                f"- Scanner: {vuln.scanner_name} | Severity: {vuln.severity} | Title: {vuln.title} | Description: {vuln.description}"
            )

        # Determine overall severity locally
        if stats["critical"] > 0:
            local_severity = "Critical"
        elif stats["high"] > 0:
            local_severity = "High"
        elif stats["medium"] > 0:
            local_severity = "Medium"
        elif stats["low"] > 0:
            local_severity = "Low"
        else:
            local_severity = "Informational"

        # Calculate a local fallback risk score (0-100 scale)
        # Critical = 35 points, High = 20 points, Medium = 8 points, Low = 2 points
        raw_score = (stats["critical"] * 35 +
                     stats["high"] * 20 +
                     stats["medium"] * 8 +
                     stats["low"] * 2)
        local_risk_score = min(100, max(0, raw_score))
        if len(vulnerabilities) > 0 and local_risk_score == 0:
            # If there are findings but risk score is 0, set to a baseline
            local_risk_score = 10

        local_summary = (
            f"AI Security Auditor completed local fallback analysis. "
            f"A total of {len(vulnerabilities)} vulnerabilities were detected: "
            f"{stats['critical']} Critical, {stats['high']} High, {stats['medium']} Medium, "
            f"and {stats['low']} Low. The overall assessed severity is {local_severity}."
        )

        # 2. Build structured prompt
        findings_text = "\n".join(findings_summary) if findings_summary else "No vulnerabilities found."
        prompt = f"""
You are an expert cybersecurity auditor. Analyze the following security scan findings and generate a structured JSON report.

Findings:
{findings_text}

Statistics:
- Critical: {stats['critical']}
- High: {stats['high']}
- Medium: {stats['medium']}
- Low: {stats['low']}
- Informational: {stats['informational']}

Return a JSON object matching this exact structure:
{{
    "summary": "Detailed overall audit summary explaining the findings and risk posture",
    "risk_score": <int between 0 and 100, where 0 is secure and 100 is critical risk>,
    "overall_severity": "<Critical/High/Medium/Low/Informational>"
}}
"""
        # 3. Call GeminiClient with try/except
        try:
            analysis = self.gemini_client.analyze_vulnerabilities(prompt)
            
            # Normalize and validate returned keys
            summary = analysis.get("summary")
            risk_score_raw = analysis.get("risk_score")
            overall_severity = analysis.get("overall_severity")

            if not summary or risk_score_raw is None or not overall_severity:
                raise ValueError("Gemini response missing required keys")

            try:
                risk_score = int(risk_score_raw)
            except (TypeError, ValueError):
                risk_score = local_risk_score

            return {
                "summary": summary,
                "risk_score": min(100, max(0, risk_score)),
                "overall_severity": overall_severity,
                "is_fallback": False
            }

        except Exception as e:
            logger.error(f"Gemini AI Analysis failed or timed out: {str(e)}. Triggering local fallback.")
            return {
                "summary": local_summary,
                "risk_score": local_risk_score,
                "overall_severity": local_severity,
                "is_fallback": True
            }
