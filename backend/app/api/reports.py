import io
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)

class ScanHistoryItem(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: str
    risk_score: float
    completed_at: datetime

class HistoryResponse(BaseModel):
    scans: List[ScanHistoryItem]
    total_count: int

@router.get("/history", response_model=HistoryResponse)
def get_scan_history():
    """
    Placeholder endpoint to retrieve the scan history.
    """
    mock_history = [
        {
            "scan_id": "scan_url_12345",
            "target": "https://example.com",
            "scan_type": "url",
            "status": "completed",
            "risk_score": 8.5,
            "completed_at": datetime.now(timezone.utc)
        },
        {
            "scan_id": "scan_file_67890",
            "target": "vulnerable_app.py",
            "scan_type": "file",
            "status": "completed",
            "risk_score": 3.2,
            "completed_at": datetime.now(timezone.utc)
        }
    ]
    return {
        "scans": mock_history,
        "total_count": len(mock_history)
    }

@router.get("/download/{scan_id}")
def download_report(scan_id: str):
    """
    Placeholder endpoint to download a security report file (PDF/Text) for a specific scan.
    """
    report_content = f"AI Security Auditor Report\nScan ID: {scan_id}\nStatus: Completed\nGenerated At: {datetime.now(timezone.utc)}"
    file_like = io.BytesIO(report_content.encode("utf-8"))
    return StreamingResponse(
        file_like,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.txt"}
    )
