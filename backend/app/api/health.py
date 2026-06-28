from fastapi import APIRouter

router = APIRouter(
    prefix="/health",
    tags=["System Health"]
)

@router.get("")
def health_check():
    """
    Service health check endpoint.
    """
    return {
        "status": "healthy",
        "database": "disconnected"
    }
