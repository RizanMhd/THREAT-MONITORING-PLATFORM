from sqlalchemy import Column, String, Text, DateTime, Integer, Float, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.orm import relationship
from app.db.session import Base
from datetime import datetime
from app.models.enums import SeverityLevel, IncidentStatus


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    key = Column(String(200), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    risk_score = Column(Float, nullable=True)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.NEW, index=True)
    owner = Column(String(100), ForeignKey("users.username"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    count = Column(Integer, default=1)
    first_event_ts = Column(Float, nullable=True)
    last_event_ts = Column(Float, nullable=True)
    ip = Column(String(45), nullable=True, index=True)
    asset_criticality = Column(String(20), nullable=True)
    detection_confidence = Column(Float, nullable=True)
    potential_impact = Column(String(20), nullable=True)

    owner_user = relationship("User", foreign_keys=[owner])
    events = relationship("IncidentEvent", back_populates="incident")
    notes = relationship(
        "InvestigationNote",
        back_populates="incident",
        order_by="InvestigationNote.created_at",
    )
    evidence = relationship("Evidence", back_populates="incident")

    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
    )

    def __repr__(self):
        return f"<Incident(id={self.id}, title={self.title}, severity={self.severity})>"