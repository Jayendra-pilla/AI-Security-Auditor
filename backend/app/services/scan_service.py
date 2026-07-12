from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime, timezone
import uuid
import time
from typing import Optional, List
import logging
from fastapi import HTTPException, status
from app.models.scan import Scan
from app.models.report import Report
from app.scanners.scanner_manager import ScannerManager
from app.services.vulnerability_service import VulnerabilityService
from app.agents.ai_analysis_agent import AIAnalysisAgent
from app.agents.recommendation_agent import RecommendationAgent
from app.agents.report_agent import ReportAgent
from app.agents.orchestrator import Orchestrator
from app.schemas.enums import ScanStatus
from app.observability.context import scan_id_var
from app.observability.metrics import MetricsService

logger = logging.getLogger(__name__)
metrics = MetricsService()

class ScanService:
    """
    Service class orchestrating security scan operations.
    """
    
    @staticmethod
    def create_scan(db: Session, user_id: int, target: str, scan_type: str) -> Scan:
        """
        Creates a new Scan record in PostgreSQL database.
        """
        scan_id_val = str(uuid.uuid4())
        db_scan = Scan(
            user_id=user_id,
            scan_id=scan_id_val,
            target=target,
            scan_type=scan_type,
            status=ScanStatus.PENDING.value,
            created_at=datetime.now(timezone.utc)
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        return db_scan

    @staticmethod
    def get_scans_by_user(db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[Scan]:
        """
        Retrieves all scans belonging to a user, sorted by created_at DESC (newest first).
        """
        stmt = select(Scan).where(Scan.user_id == user_id).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
        return list(db.execute(stmt).scalars().all())

    @staticmethod
    def get_scan_by_public_id(db: Session, scan_id: str) -> Optional[Scan]:
        """
        Retrieves a single scan by its public UUID string (scan_id).
        """
        stmt = select(Scan).where(Scan.scan_id == scan_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def delete_scan(db: Session, scan: Scan) -> bool:
        """
        Deletes the scan from PostgreSQL. Cascades will handle related tables.
        """
        db.delete(scan)
        db.commit()
        return True

    @staticmethod
    def execute_scan(
        db: Session,
        scan: Scan,
        scanner_manager: Optional[ScannerManager] = None
    ) -> dict:
        """
        Executes all configured scanners against the scan target.
        Updates the scan record status in the database to 'running', 'completed', or 'failed' accordingly.
        """
        if scanner_manager is None:
            scanner_manager = ScannerManager()

        # Set observability context
        scan_id_var.set(scan.scan_id)
        scan_start = time.perf_counter()

        logger.info(f"Starting scan for target: {scan.target} (ID: {scan.scan_id})")
        scan.status = ScanStatus.RUNNING.value
        try:
            db.commit()
            db.refresh(scan)
            logger.info(f"Scan running: {scan.scan_id}")
        except Exception as commit_err:
            logger.exception(f"Failed to update scan status to running for scan {scan.scan_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initialize scan status in database."
            )

        try:
            # Timed: Scanner execution
            scanner_start = time.perf_counter()
            results = scanner_manager.run_all_scanners(scan.target)
            scanner_duration_ms = round((time.perf_counter() - scanner_start) * 1000, 2)
            logger.info(f"All scanners completed in {scanner_duration_ms}ms for scan {scan.scan_id}")
            
            # Run Orchestrator agent analysis layer (purely additive, no schema changes)
            orchestrator = Orchestrator()
            agent_analysis = orchestrator.analyze(results)
            logger.info(
                f"Orchestrator analysis completed: {agent_analysis.get('overall_severity', 'N/A')} severity, "
                f"{agent_analysis.get('total_findings', 0)} findings"
            )
            
            # Persist scanner findings to PostgreSQL
            vulnerabilities = VulnerabilityService.save_scan_results(db, scan, results)
            
            # Run AI Analysis Pipeline & Intelligent Report Generation
            ai_analysis_agent = AIAnalysisAgent()
            recommendation_agent = RecommendationAgent()
            report_agent = ReportAgent()
            
            # Timed: AI Analysis
            ai_start = time.perf_counter()
            ai_analysis = ai_analysis_agent.analyze(vulnerabilities)
            ai_duration_ms = round((time.perf_counter() - ai_start) * 1000, 2)
            logger.info(f"AI analysis completed in {ai_duration_ms}ms for scan {scan.scan_id}")
            metrics.record_ai_analysis(ai_duration_ms)
            
            # 2. Compile Recommendations
            recs = recommendation_agent.generate_recommendations(vulnerabilities)
            
            # Timed: Report Generation
            report_start = time.perf_counter()
            report_payload = report_agent.generate_report(
                risk_score=ai_analysis["risk_score"],
                summary=ai_analysis["summary"],
                vulnerabilities=vulnerabilities,
                recommendations=recs
            )
            report_duration_ms = round((time.perf_counter() - report_start) * 1000, 2)
            logger.info(f"Report generation completed in {report_duration_ms}ms for scan {scan.scan_id}")
            
            # 4. Persist the report record to PostgreSQL
            db_report = Report(
                scan_id=scan.scan_id,
                scan_db_id=scan.id,
                risk_score=report_payload["risk_score"],
                grade=report_payload["grade"],
                summary=report_payload["summary"],
                statistics=report_payload["statistics"],
                recommendations=report_payload["recommendations"],
                completed_at=datetime.now(timezone.utc)
            )
            db.add(db_report)
            
            scan.status = ScanStatus.COMPLETED.value
            db.commit()
            db.refresh(scan)

            # Record metrics
            total_duration_ms = round((time.perf_counter() - scan_start) * 1000, 2)
            metrics.record_scan(total_duration_ms, success=True)
            logger.info(f"Scan completed: {scan.scan_id} | total_duration_ms={total_duration_ms}")

            return results
        except Exception as scan_err:
            total_duration_ms = round((time.perf_counter() - scan_start) * 1000, 2)
            metrics.record_scan(total_duration_ms, success=False)
            logger.exception(f"Scan failed: {scan.scan_id} | total_duration_ms={total_duration_ms}")
            try:
                scan.status = ScanStatus.FAILED.value
                db.commit()
                db.refresh(scan)
            except Exception as commit_fail_err:
                logger.exception(f"Failed to commit 'failed' status for scan {scan.scan_id}")
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan execution failed due to an internal error."
            )


