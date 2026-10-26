from sqlalchemy import Column, Integer, String, Text, DateTime, Index, Float
from app.db.session import Base
from datetime import datetime


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ts = Column(Float, nullable=False, index=True)
    user = Column(String(100), nullable=False, index=True)
    action = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_audit_logs_user_ts", "user", "ts"),
    )

    def __repr__(self):
        return f"<AuditLog(id={self.id}, user={self.user}, action={self.action[:50]})>"