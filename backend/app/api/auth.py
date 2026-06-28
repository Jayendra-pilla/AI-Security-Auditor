from fastapi import APIRouter, status
from pydantic import BaseModel

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

class UserRegister(BaseModel):
    email: str
    username: str
    password: str

class UserLogin(BaseModel):
    username_or_email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister):
    """
    Placeholder endpoint to register a new user.
    """
    return {
        "id": 1,
        "email": user_data.email,
        "username": user_data.username,
        "is_active": True
    }

@router.post("/login", response_model=TokenResponse)
def login(login_data: UserLogin):
    """
    Placeholder endpoint to log in a user and return a JWT access token.
    """
    return {
        "access_token": "placeholder_jwt_token_here",
        "token_type": "bearer"
    }
