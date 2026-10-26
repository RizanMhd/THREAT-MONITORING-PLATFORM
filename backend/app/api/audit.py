from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.session import get_db
from app.models import AuditLog
from app.models.enums import UserRole


router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[dict])
def get_audit_logs(
    limit: int = 300,
    user: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    query = db.query(AuditLog).order_by(AuditLog.ts.desc())
    if user:
        query = query.filter(AuditLog.user == user)
    logs = query.limit(min(max(limit, 1), 1000)).all()

    return [
        {
            "id": log.id,
            "timestamp": log.ts,
            "user": log.user,
            "action": log.action,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
        }
        for log in logs
    ]
