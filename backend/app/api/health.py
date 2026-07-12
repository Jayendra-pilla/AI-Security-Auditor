import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database.db import get_db
from app.config import settings

# Track application start time for uptime calculation
_start_time = time.time()

router = APIRouter(
    prefix="/health",
    tags=["System Health"]
)

@router.get("")
def health_check(db: Session = Depends(get_db)):
    """
    Service health check endpoint. Verifies database connectivity,
    Gemini API availability, application version, and uptime.
    """
    # Database check
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    # Gemini availability check (non-blocking — config only, no API call)
    gemini_key = settings.GEMINI_API_KEY
    if gemini_key and gemini_key not in ("your-gemini-api-key", "", "None"):
        gemini_status = "available"
    else:
        gemini_status = "unavailable"

    # Uptime
    uptime_seconds = round(time.time() - _start_time, 1)

    return {
        "status": "healthy",
        "database": db_status,
        "gemini": gemini_status,
        "version": settings.APP_VERSION,
        "uptime_seconds": uptime_seconds,
    }
