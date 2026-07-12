from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.schemas.auth import UserRegister, Token
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService
from app.auth.dependencies import get_current_user
from app.models.user import User

from app.observability.rate_limiter import RateLimiter

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

limiter_auth = RateLimiter(requests_limit=5, window_seconds=60)

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(limiter_auth)])
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user after validating email, username, and password strength.
    """
    # Reject duplicate username
    if AuthService.get_user_by_username(db, user_data.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered"
        )
        
    # Reject duplicate email
    if AuthService.get_user_by_email(db, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
        
    user = AuthService.register_user(db, user_data)
    return user

@router.post("/login", response_model=Token, dependencies=[Depends(limiter_auth)])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Authenticate a user via username/email and password.
    Supports standard URL-encoded Form data (used by OAuth2 / Swagger UI).
    """
    user = AuthService.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user. Please contact support."
        )
        
    # Update last login time
    AuthService.update_last_login(db, user)
    
    access_token = AuthService.create_access_token(user)
    return Token(
        access_token=access_token,
        token_type="bearer"
    )

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Get the currently authenticated user's profile details.
    """
    return current_user
