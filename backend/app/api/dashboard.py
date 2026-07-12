import logging
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from typing import List

from app.schemas.dashboard import (
    DashboardOverviewResponse,
    RecentScanResponse,
    RiskDistributionResponse,
    TopVulnerabilityResponse,
    DashboardStatisticsResponse,
    DashboardTrendResponse,
    HistoryResponse
)
from app.services.dashboard_service import DashboardService

logger = logging.getLogger(__name__)

from app.observability.rate_limiter import RateLimiter

limiter_dashboard = RateLimiter(requests_limit=60, window_seconds=60)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(limiter_dashboard)]
)

@router.get("/overview", response_model=DashboardOverviewResponse)
def get_dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/overview for user {current_user.id}")
    try:
        data = DashboardService.get_overview(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/overview for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/overview for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard overview."
        )

@router.get("/recent-scans", response_model=List[RecentScanResponse])
def get_recent_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/recent-scans for user {current_user.id}")
    try:
        data = DashboardService.get_recent_scans(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/recent-scans for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/recent-scans for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve recent scans."
        )

@router.get("/risk-distribution", response_model=RiskDistributionResponse)
def get_risk_distribution(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/risk-distribution for user {current_user.id}")
    try:
        data = DashboardService.get_risk_distribution(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/risk-distribution for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/risk-distribution for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve risk distribution."
        )

@router.get("/top-vulnerabilities", response_model=List[TopVulnerabilityResponse])
def get_top_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/top-vulnerabilities for user {current_user.id}")
    try:
        data = DashboardService.get_top_vulnerabilities(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/top-vulnerabilities for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/top-vulnerabilities for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve top vulnerabilities."
        )

@router.get("/history", response_model=List[HistoryResponse])
def get_dashboard_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/history for user {current_user.id}")
    try:
        data = DashboardService.get_history(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/history for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/history for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard history."
        )

@router.get("/statistics", response_model=DashboardStatisticsResponse)
def get_dashboard_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/statistics for user {current_user.id}")
    try:
        data = DashboardService.get_statistics(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/statistics for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/statistics for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard statistics."
        )

@router.get("/trends", response_model=List[DashboardTrendResponse])
def get_dashboard_trends(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Dashboard request received: GET /dashboard/trends for user {current_user.id}")
    try:
        data = DashboardService.get_trends(db, current_user.id)
        logger.info(f"Dashboard response sent: GET /dashboard/trends for user {current_user.id}")
        return data
    except Exception as e:
        logger.error(f"Error occurred in dashboard: GET /dashboard/trends for user {current_user.id}. Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard trends."
        )
