from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.scan import Scan

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(index=True)
    scan_db_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    user_id: Mapped[int] = mapped_column(index=True)
    status: Mapped[str] = mapped_column()
    completed_at: Mapped[datetime] = mapped_column()

    scan: Mapped["Scan"] = relationship(back_populates="history_records")

