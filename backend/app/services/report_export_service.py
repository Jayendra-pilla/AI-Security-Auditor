from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.models.user import User
from app.services.scan_service import ScanService

# Import Generators
from app.reports.html_generator import HTMLReportGenerator
from app.reports.pdf_generator import PDFReportGenerator
from app.reports.markdown_generator import MarkdownReportGenerator
from app.reports.json_export import JSONExportGenerator

class ReportExportService:
    """
    Service layer coordinating professional report formatting and exports.
    """

    @staticmethod
    def _get_verified_scan_and_report(db: Session, scan_id: str, current_user: User):
        """
        Helper method to verify scan and report existence, and enforce ownership.
        """
        scan = ScanService.get_scan_by_public_id(db, scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        if scan.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        report = scan.report
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )
            
        return scan, report

    @classmethod
    def export_html(cls, db: Session, scan_id: str, current_user: User) -> str:
        """
        Verifies ownership and compiles report as an HTML document.
        """
        scan, report = cls._get_verified_scan_and_report(db, scan_id, current_user)
        return HTMLReportGenerator.generate(scan, report)

    @classmethod
    def export_pdf(cls, db: Session, scan_id: str, current_user: User) -> bytes:
        """
        Verifies ownership and compiles report as a ReportLab PDF document.
        """
        scan, report = cls._get_verified_scan_and_report(db, scan_id, current_user)
        return PDFReportGenerator.generate(scan, report)

    @classmethod
    def export_markdown(cls, db: Session, scan_id: str, current_user: User) -> str:
        """
        Verifies ownership and compiles report as a technical GitHub Markdown document.
        """
        scan, report = cls._get_verified_scan_and_report(db, scan_id, current_user)
        return MarkdownReportGenerator.generate(scan, report)

    @classmethod
    def export_json(cls, db: Session, scan_id: str, current_user: User) -> str:
        """
        Verifies ownership and compiles report as structured JSON content.
        """
        scan, report = cls._get_verified_scan_and_report(db, scan_id, current_user)
        return JSONExportGenerator.generate(scan, report)
