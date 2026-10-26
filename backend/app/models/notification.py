from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum as SQLEnum
from app.db.session import Base
from datetime import datetime
from app.models.enums import NotificationChannel, NotificationStatus


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    recipient = Column(String(100), ForeignKey("users.username"), nullable=False, index=True)
    channel = Column(SQLEnum(NotificationChannel), default=NotificationChannel.IN_APP)
    subject = Column(String(255), nullable=True)
    message = Column(Text, nullable=False)
    status = Column(SQLEnum(NotificationStatus), default=NotificationStatus.PENDING, index=True)
    sent_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<Notification(id={self.id}, recipient={self.recipient}, channel={self.channel})>"