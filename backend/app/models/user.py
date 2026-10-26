from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum as SQLEnum, String

from app.db.session import Base
from app.models.enums import UserRole


class User(Base):
    __tablename__ = "users"

    username = Column(String(100), primary_key=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.VIEWER)
    email = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User(username={self.username}, role={self.role})>"