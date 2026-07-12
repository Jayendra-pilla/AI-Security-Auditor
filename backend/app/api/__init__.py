from app.api.auth import router as auth_router
from app.api.scan import router as scan_router
from app.api.reports import router as reports_router
from app.api.history import router as history_router
from app.api.health import router as health_router
from app.api.dashboard import router as dashboard_router

__all__ = ["auth_router", "scan_router", "reports_router", "history_router", "health_router", "dashboard_router"]

