import logging
from typing import Dict, Any, List
from app.agents.recon_agent import ReconAgent, _max_severity
from app.agents.header_agent import HeaderAgent
from app.agents.ssl_agent import SSLAgent
from app.agents.tech_agent import TechAgent
from app.agents.endpoint_agent import EndpointAgent

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Master orchestrator that coordinates all domain-level security agents.

    Receives the full results dict from ScannerManager.run_all_scanners(),
    distributes scanner outputs to the appropriate domain agents, and compiles
    a combined intelligence report with an executive summary.
    """

    def __init__(self) -> None:
        self.agents = [
            ("recon", ReconAgent()),
            ("headers", HeaderAgent()),
            ("ssl", SSLAgent()),
            ("tech", TechAgent()),
            ("endpoints", EndpointAgent()),
        ]

    def analyze(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run all domain agents against the scanner results and produce
        a combined orchestration report.

        Args:
            results: The full dict returned by ScannerManager.run_all_scanners().

        Returns:
            A dictionary containing individual agent reports plus an executive summary.
        """
        logger.info("Orchestrator analysis started.")

        # Apply cross-scanner correlation (Phase 6 requirement)
        try:
            from app.scanners.correlation_engine import correlate_findings
            results = correlate_findings(results)
        except Exception as corr_err:
            logger.error(f"Orchestrator: Correlation step failed: {str(corr_err)}")

        agent_reports: Dict[str, Any] = {}
        overall_severity = "Informational"
        total_findings = 0
        agents_executed = 0

        for agent_key, agent_instance in self.agents:
            try:
                report = agent_instance.analyze(results)
                agent_reports[agent_key] = report
                agents_executed += 1

                # Roll up severity and findings
                agent_sev = report.get("max_severity", "Informational")
                overall_severity = _max_severity(overall_severity, agent_sev)
                total_findings += report.get("finding_count", 0)

            except Exception as e:
                logger.error(
                    f"Orchestrator: Agent '{agent_key}' failed with error: {str(e)}"
                )
                agent_reports[agent_key] = {
                    "agent": agent_instance.__class__.__name__,
                    "status": "failed",
                    "error": str(e),
                }

        executive_summary = (
            f"Security orchestration completed. "
            f"{agents_executed} domain agents executed across all scanner results. "
            f"{total_findings} total findings detected. "
            f"Overall assessed severity: {overall_severity}."
        )

        orchestration_report = {
            "status": "completed",
            "overall_severity": overall_severity,
            "total_findings": total_findings,
            "agents_executed": agents_executed,
            "executive_summary": executive_summary,
            "agent_reports": agent_reports,
        }

        logger.info(
            f"Orchestrator analysis completed: {overall_severity} severity, "
            f"{total_findings} findings, {agents_executed} agents."
        )
        return orchestration_report
