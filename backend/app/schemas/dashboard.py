from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, List
from app.schemas.enums import ScanStatus

class DashboardOverviewResponse(BaseModel):
    total_scans: int
    completed_scans: int
    running_scans: int
    failed_scans: int
    total_reports: int
    total_vulnerabilities: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    informational_findings: int
    average_risk_score: float
    latest_grade: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class RecentScanResponse(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: ScanStatus
    risk_score: Optional[float] = None
    grade: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class RiskDistributionResponse(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    total: int

    model_config = ConfigDict(from_attributes=True)

class TopVulnerabilityResponse(BaseModel):
    title: str
    severity: str
    count: int

    model_config = ConfigDict(from_attributes=True)

class DashboardStatisticsResponse(BaseModel):
    average_risk_score: float
    highest_risk_score: float
    lowest_risk_score: float
    average_findings_per_scan: float
    total_reports: int

    model_config = ConfigDict(from_attributes=True)

class DashboardTrendResponse(BaseModel):
    date: str
    risk_score: float

    model_config = ConfigDict(from_attributes=True)

class HistoryResponse(BaseModel):
    scan_id: str
    target: str
    status: ScanStatus
    grade: Optional[str] = None
    risk_score: Optional[float] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
