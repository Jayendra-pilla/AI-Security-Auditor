from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import List, Dict, Any
from app.schemas.enums import ScanStatus

class ScanHistoryItem(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: ScanStatus
    risk_score: float
    completed_at: datetime

    model_config = ConfigDict(from_attributes=True)

class HistoryResponse(BaseModel):
    scans: List[ScanHistoryItem]
    total_count: int

    model_config = ConfigDict(from_attributes=True)

class StatisticsSchema(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int

    model_config = ConfigDict(from_attributes=True)

class RecommendationSchema(BaseModel):
    recommendation: str

    model_config = ConfigDict(from_attributes=True)

class ReportResponse(BaseModel):
    scan_id: str
    grade: str
    risk_score: float
    summary: str
    statistics: StatisticsSchema
    recommendations: List[str]

    model_config = ConfigDict(from_attributes=True)
