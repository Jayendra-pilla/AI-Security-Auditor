from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth_router, scan_router, reports_router, history_router, health_router, dashboard_router

from app.database.base import Base
from app.database.session import engine
import app.models

# Initialize structured logging and DNS security patch before anything else
from app.config import settings
from app.observability.logging_config import setup_logging
from app.observability.ssrf_prevention import install_dns_patch

setup_logging(log_level=settings.LOG_LEVEL)
install_dns_patch()

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Security Auditor API",
    version=settings.APP_VERSION
)

# CORS Middleware — allow the React frontend to communicate with the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Logging Middleware — tracing, duration, X-Request-ID
from app.observability.middleware import RequestLoggingMiddleware
app.add_middleware(RequestLoggingMiddleware, enable_logging=settings.ENABLE_REQUEST_LOGGING)

# Register API Routers
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(health_router)
app.include_router(dashboard_router)


@app.get("/")
def root():
    return {
        "message": "AI Security Auditor Backend is Running 🚀"
    }

# ---------------------------------------------------------------------------
# Global Exception Handler (prevents leaking internal details/stack traces)
# ---------------------------------------------------------------------------
import logging
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}")
    
    if isinstance(exc, StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
    if isinstance(exc, RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors()}
        )
        
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."}
    )