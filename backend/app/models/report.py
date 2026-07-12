from sqlalchemy import ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base
from datetime import datetime
from typing import TYPE_CHECKING, Optional, List, Dict, Any

if TYPE_CHECKING:
    from app.models.scan import Scan

class Report(Base):
    __tablename__ = "reports"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(unique=True, index=True)
    scan_db_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True, index=True)
    risk_score: Mapped[float] = mapped_column()
    completed_at: Mapped[datetime] = mapped_column()
    
    summary: Mapped[Optional[str]] = mapped_column(nullable=True)
    grade: Mapped[Optional[str]] = mapped_column(nullable=True)
    recommendations: Mapped[List[str]] = mapped_column(JSON, default=list)
    statistics: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped["Scan"] = relationship(back_populates="report")

