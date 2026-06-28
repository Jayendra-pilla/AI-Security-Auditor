from typing import Generator
from app.database.session import SessionLocal

def get_db() -> Generator:
    """
    Dependency to obtain database session context.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
