from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List
from datetime import datetime
from sqlalchemy.orm import Session
from app.schemas.enums import ScanStatus

from app.database.db import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.report import Report

router = APIRouter(
    prefix="/history",
    tags=["Scan History"]
)

class ScanHistoryItem(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: ScanStatus
    risk_score: float
    completed_at: datetime

class HistoryListResponse(BaseModel):
    history: List[ScanHistoryItem]
    total: int

@router.get("", response_model=HistoryListResponse)
def get_scan_history_list(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve the list of scan history records for the authenticated user from the database.
    """
    from sqlalchemy import select, func
    
    # Get total count
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
        
        history_items.append(
            ScanHistoryItem(
                scan_id=scan.scan_id,
                target=scan.target,
                scan_type=scan.scan_type,
                status=scan.status,
                risk_score=float(risk),
                completed_at=comp_at
            )
        )
        
    return HistoryListResponse(
        history=history_items,
        total=total_count
    )

