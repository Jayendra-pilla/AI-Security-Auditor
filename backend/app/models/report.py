from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base
from datetime import datetime

class Report(Base):
    __tablename__ = "reports"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(unique=True, index=True)
    risk_score: Mapped[float] = mapped_column()
    completed_at: Mapped[datetime] = mapped_column()
