import enum


class UserRole(str, enum.Enum):
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    VIEWER = "VIEWER"


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, enum.Enum):
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class NoteKind(str, enum.Enum):
    EVENT = "event"
    NOTE = "note"
    SYSTEM = "system"


class NotificationChannel(str, enum.Enum):
    EMAIL = "email"
    IN_APP = "in_app"
    SNS = "sns"


class NotificationStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"