import io
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, status, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.report import HistoryResponse, ReportResponse
from app.services.scan_service import ScanService
from app.models.report import Report
from app.models.scan import Scan
from app.services.report_export_service import ReportExportService

from app.observability.rate_limiter import RateLimiter

limiter_reports = RateLimiter(requests_limit=30, window_seconds=60)

router = APIRouter(
    tags=["Reports"],
    dependencies=[Depends(limiter_reports)]
)

@router.get("/reports/history", response_model=HistoryResponse)
def get_scan_history(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve the scan reports history for the authenticated user from the database.
    """
    from sqlalchemy import select, func
    
    total_count = db.execute(select(func.count(Scan.id)).where(Scan.user_id == current_user.id)).scalar() or 0
    
    stmt = (
        select(Scan, Report)
        .outerjoin(Report, Scan.id == Report.scan_db_id)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    results = db.execute(stmt).all()
    
    history_items = []
    for scan, report in results:
        risk = report.risk_score if report else 0.0
        comp_at = report.completed_at if report else scan.created_at
        
        history_items.append({
            "scan_id": scan.scan_id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "risk_score": float(risk),
            "completed_at": comp_at
        })
        
    return {
        "scans": history_items,
        "total_count": total_count
    }

@router.get("/reports/download/{scan_id}")
def download_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download a security report file (Markdown) for a specific scan. Only accessible by the scan owner.
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
    
    report_title = f"# AI Security Audit Report for {scan.target}\n"
    meta_info = (
        f"**Scan ID:** {scan.scan_id}  \n"
        f"**Scan Type:** {scan.scan_type}  \n"
        f"**Status:** {scan.status}  \n"
        f"**Generated At:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n\n"
    )
    
    if report:
        summary_section = (
            f"## Executive Summary\n"
            f"**Overall Grade:** {report.grade}  \n"
            f"**Assessed Risk Score:** {report.risk_score}/100  \n\n"
            f"### Analysis Summary\n"
            f"{report.summary}\n\n"
        )
        
        stats = report.statistics or {}
        stats_section = (
            f"## Severity Statistics\n"
            f"- Critical: {stats.get('critical', 0)}\n"
            f"- High: {stats.get('high', 0)}\n"
            f"- Medium: {stats.get('medium', 0)}\n"
            f"- Low: {stats.get('low', 0)}\n"
            f"- Informational: {stats.get('informational', 0)}\n\n"
        )
        
        recs = report.recommendations or []
        recs_section = "## Actionable Recommendations\n"
        if recs:
            for i, rec in enumerate(recs, 1):
                recs_section += f"{i}. {rec}\n"
        else:
            recs_section += "No recommendations needed.\n"
        recs_section += "\n"
        
        report_content = report_title + meta_info + summary_section + stats_section + recs_section
    else:
        report_content = (
            report_title + meta_info +
            "## Scan Status\n"
            "This scan has not completed successfully or is currently pending/running. No report is available yet.\n"
        )
        
    file_like = io.BytesIO(report_content.encode("utf-8"))
    return StreamingResponse(
        file_like,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.md"}
    )


@router.get("/report/{scan_id}", response_model=ReportResponse)
def get_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve the AI-generated security report for a specific scan.
    Only accessible by the scan owner.
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

    return report


@router.get("/report/{scan_id}/html")
def get_report_html(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download/view the security report as a styled HTML page.
    """
    html_content = ReportExportService.export_html(db, scan_id, current_user)
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.html"}
    )


@router.get("/report/{scan_id}/pdf")
def get_report_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download the security report as a printable PDF.
    """
    pdf_bytes = ReportExportService.export_pdf(db, scan_id, current_user)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"}
    )


@router.get("/report/{scan_id}/markdown")
def get_report_markdown(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download the security report as a technical GitHub Markdown file.
    """
    markdown_content = ReportExportService.export_markdown(db, scan_id, current_user)
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.md"}
    )


@router.get("/report/{scan_id}/json")
def get_report_json(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download the complete security report data as a structured JSON file.
    """
    json_str = ReportExportService.export_json(db, scan_id, current_user)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"}
    )

