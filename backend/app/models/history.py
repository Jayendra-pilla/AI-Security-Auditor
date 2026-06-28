from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base
from datetime import datetime

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(index=True)
    user_id: Mapped[int] = mapped_column(index=True)
    status: Mapped[str] = mapped_column()
    completed_at: Mapped[datetime] = mapped_column()
