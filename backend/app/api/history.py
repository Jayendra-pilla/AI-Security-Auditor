from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from datetime import datetime, timezone

router = APIRouter(
    prefix="/history",
    tags=["Scan History"]
)

class ScanHistoryItem(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: str
    risk_score: float
    completed_at: datetime

class HistoryListResponse(BaseModel):
    history: List[ScanHistoryItem]
    total: int

@router.get("", response_model=HistoryListResponse)
def get_scan_history_list():
    """
    Placeholder endpoint to retrieve list of scan history records.
    """
    return {
        "history": [],
        "total": 0
    }
