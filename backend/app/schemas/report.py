from pydantic import BaseModel
from datetime import datetime
from typing import List

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
