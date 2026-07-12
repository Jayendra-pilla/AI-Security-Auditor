from sqlalchemy import select
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import Optional

from app.models.user import User
from app.schemas.auth import UserRegister
from app.auth.password import PasswordHasher
from app.auth.jwt_handler import JWTHandler

class AuthService:
    """
    Service class handling user authentication business logic.
    """
    
    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
        """
        Retrieve a user from the database by their ID.
        """
        stmt = select(User).where(User.id == user_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """
        Retrieve a user from the database by their email.
        """
        stmt = select(User).where(User.email == email)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        """
        Retrieve a user from the database by their username.
        """
        stmt = select(User).where(User.username == username)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def register_user(db: Session, user_data: UserRegister) -> User:
        """
        Register a new user in the database.
        """
        hashed_pw = PasswordHasher.hash_password(user_data.password)
        db_user = User(
            email=user_data.email,
            username=user_data.username,
            hashed_password=hashed_pw,
            role=user_data.role,
            is_active=True
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    @staticmethod
    def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[User]:
        """
        Authenticate a user by email or username, checking the password hash.
        """
        # Attempt lookup by username first
        user = AuthService.get_user_by_username(db, username_or_email)
        if not user:
            # Fallback to email lookup
            user = AuthService.get_user_by_email(db, username_or_email)
            
        if not user:
            return None
            
        if not PasswordHasher.verify_password(password, user.hashed_password):
            return None
            
        return user

    @staticmethod
    def update_last_login(db: Session, user: User) -> None:
        """
        Update the user's last_login timestamp in the database.
        """
        user.last_login = datetime.now(timezone.utc)
        db.add(user)
        db.commit()
        db.refresh(user)

    @staticmethod
    def create_access_token(user: User) -> str:
        """
        Create a JWT token for the user containing relevant details.
        """
        payload = {
            "sub": str(user.id),
            "email": user.email,
            "username": user.username,
            "role": user.role
        }
        return JWTHandler.create_access_token(data=payload)
