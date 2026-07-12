from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional

from app.database.db import get_db
from app.auth.jwt_handler import JWTHandler
from app.schemas.auth import TokenData
from app.services.auth_service import AuthService
from app.models.user import User

# tokenUrl must point to our login route
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """
    FastAPI dependency to retrieve the current authenticated user from JWT bearer token.
    Raises 401 for invalid/expired tokens and 404/400 for missing/inactive users.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = JWTHandler.decode_token(token)
    if payload is None:
        raise credentials_exception
        
    user_id_str: Optional[str] = payload.get("sub")
    email: Optional[str] = payload.get("email")
    username: Optional[str] = payload.get("username")
    role: Optional[str] = payload.get("role")
    
    if user_id_str is None:
        raise credentials_exception
        
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise credentials_exception
        
    token_data = TokenData(id=user_id, email=email, username=username, role=role)
    
    # Retrieve user from database
    user = AuthService.get_user_by_id(db, user_id=token_data.id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
        
    return user

class AuthDependencies:
    """
    Authentication dependencies for FastAPI endpoints (e.g. current_user).
    """
    oauth2_scheme = oauth2_scheme
    
    @staticmethod
    def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
        return get_current_user(token, db)
