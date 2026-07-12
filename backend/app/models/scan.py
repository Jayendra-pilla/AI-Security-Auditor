from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.report import Report
    from app.models.history import ScanHistory
    from app.models.vulnerability import Vulnerability

class Scan(Base):
    __tablename__ = "scans"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column()
    target: Mapped[str] = mapped_column()
    scan_type: Mapped[str] = mapped_column()
    created_at: Mapped[datetime] = mapped_column()

    user: Mapped["User"] = relationship(back_populates="scans")
    report: Mapped[Optional["Report"]] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")
    history_records: Mapped[List["ScanHistory"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

