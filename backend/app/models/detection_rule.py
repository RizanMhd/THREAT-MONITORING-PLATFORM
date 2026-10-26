from sqlalchemy import Column, String, Text, Integer, Enum as SQLEnum
from app.db.session import Base
from app.models.enums import SeverityLevel


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    condition = Column(Text, nullable=False)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    enabled = Column(Integer, default=1)
    threshold = Column(Integer, nullable=True)
    time_window_seconds = Column(Integer, nullable=True)
    created_at = Column(String(50), nullable=False)
    updated_at = Column(String(50), nullable=True)

    def __repr__(self):
        return f"<DetectionRule(id={self.id}, name={self.name}, severity={self.severity})>"