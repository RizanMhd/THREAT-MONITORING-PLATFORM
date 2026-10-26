from sqlalchemy import Column, String, DateTime, Integer, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base
from datetime import datetime


class LogSource(Base):
    __tablename__ = "log_sources"

    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    source_type = Column(String(50), nullable=False)
    config = Column(JSON, nullable=True)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    events = relationship("Event", back_populates="source")

    def __repr__(self):
        return f"<LogSource(id={self.id}, name={self.name})>"