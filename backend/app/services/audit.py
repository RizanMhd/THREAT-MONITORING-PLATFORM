import time

from sqlalchemy.orm import Session

from app.models import AuditLog


def record_audit(
    db: Session,
    user: str,
    action: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        ts=time.time(),
        user=user,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(entry)
    return entry
