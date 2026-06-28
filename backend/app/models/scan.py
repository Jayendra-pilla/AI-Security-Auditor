from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base
from datetime import datetime

class Scan(Base):
    __tablename__ = "scans"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(unique=True, index=True)
    status: Mapped[str] = mapped_column()
    target: Mapped[str] = mapped_column()
    scan_type: Mapped[str] = mapped_column()
    created_at: Mapped[datetime] = mapped_column()
