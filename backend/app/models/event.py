from sqlalchemy import Column, String, Text, DateTime, Integer, Float, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base
from datetime import datetime


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ts = Column(Float, nullable=False, index=True)
    source_id = Column(String(50), ForeignKey("log_sources.id"), nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    user = Column(String(100), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    country = Column(String(2), nullable=True)
    detail = Column(Text, nullable=True)
    role = Column(String(50), nullable=True)
    raw_data = Column(JSON, nullable=True)
    hit = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    source = relationship("LogSource", back_populates="events")
    incident_events = relationship("IncidentEvent", back_populates="event")

    __table_args__ = (
        Index("ix_events_ip_type_ts", "ip", "event_type", "ts"),
        Index("ix_events_user_ts", "user", "ts"),
    )

    def __repr__(self):
        return f"<Event(id={self.id}, ip={self.ip}, type={self.event_type})>"