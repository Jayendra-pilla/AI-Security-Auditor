from fastapi import FastAPI
from app.api import auth_router, scan_router, reports_router, history_router, health_router

from app.database.base import Base
from app.database.session import engine
import app.models

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Security Auditor API",
    version="1.0.0"
)
# Register API Routers
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(health_router)

@app.get("/")
def root():
    return {
        "message": "AI Security Auditor Backend is Running 🚀"
    }