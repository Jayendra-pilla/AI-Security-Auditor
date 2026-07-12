from fastapi import APIRouter, UploadFile, File, status, Depends, HTTPException
from datetime import datetime, timezone
from typing import List
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.scan import ScanCreateRequest, ScanCreateResponse, ScanResponse, ScanDetailResponse
from app.schemas.vulnerability import ScanResultsResponse
from app.services.scan_service import ScanService

from app.observability.rate_limiter import RateLimiter

router = APIRouter(
    prefix="/scan",
    tags=["Scans"]
)

limiter_scan = RateLimiter(requests_limit=10, window_seconds=60)

@router.post("", response_model=ScanCreateResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(limiter_scan)])
def create_scan(
    request: ScanCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submit a new security scan request for the authenticated user.
    """
    scan = ScanService.create_scan(
        db=db,
        user_id=current_user.id,
        target=request.target,
        scan_type=request.scan_type
    )
    results = ScanService.execute_scan(db, scan)
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "results": results
    }

@router.get("", response_model=List[ScanResponse])
def get_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve all scans belonging to the authenticated user, sorted by newest first.
    """
    return ScanService.get_scans_by_user(db, current_user.id, skip, limit)

@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve full details of a single scan. Accessible only by the scan owner.
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
    return scan

@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete a scan. Accessible only by the scan owner. Cascades to report and history.
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
    ScanService.delete_scan(db, scan)
    return {"message": "Scan deleted successfully"}

@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
def get_scan_results(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve vulnerability findings of a completed scan. Accessible only by the owner.
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
        
    return {
        "scan_id": scan.scan_id,
        "total_findings": len(scan.vulnerabilities),
        "results": scan.vulnerabilities
    }

@router.post("/url", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(limiter_scan)])
def scan_url(
    request: ScanCreateRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Submit a URL for security auditing.
    """
    return {
        "scan_id": "scan_url_12345",
        "status": "queued",
        "target": request.target,
        "scan_type": "url",
        "created_at": datetime.now(timezone.utc)
    }

@router.post("/file", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(limiter_scan)])
def scan_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Placeholder endpoint to upload and scan a file for security audit.
    """
    return {
        "scan_id": "scan_file_67890",
        "status": "queued",
        "target": file.filename,
        "scan_type": "file",
        "created_at": datetime.now(timezone.utc)
    }
