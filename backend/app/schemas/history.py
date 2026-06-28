from pydantic import BaseModel
from datetime import datetime
from typing import List

class ScanHistoryItemSchema(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: str
    risk_score: float
    completed_at: datetime

class HistoryListResponseSchema(BaseModel):
    history: List[ScanHistoryItemSchema]
    total: int
