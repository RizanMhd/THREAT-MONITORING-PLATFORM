from sqlalchemy import Column, Integer, Text, DateTime, ForeignKey, String, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.db.session import Base
from datetime import datetime
from app.models.enums import NoteKind


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    kind = Column(SQLEnum(NoteKind), default=NoteKind.NOTE)
    text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    incident = relationship("Incident", back_populates="notes")

    def __repr__(self):
        return f"<InvestigationNote(id={self.id}, incident_id={self.incident_id}, author={self.author})>"