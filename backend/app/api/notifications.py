from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from app.db.session import get_db
from app.models import Notification
from app.api.auth import require_role
from app.models.user import UserRole
from app.core.time import utc_iso


router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=List[dict])
def get_my_notifications(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SECURITY_MANAGER, UserRole.VIEWER)),
):
    notifications = db.query(Notification).filter(
        Notification.recipient == current_user.username
    ).order_by(Notification.created_at.desc()).limit(limit).all()

    return [
        {
            "id": n.id,
            "incident_id": n.incident_id,
            "channel": n.channel.value,
            "subject": n.subject,
            "message": n.message,
            "status": n.status.value,
            "sent_at": utc_iso(n.sent_at),
            "created_at": utc_iso(n.created_at),
        }
        for n in notifications
    ]


@router.post("/{notification_id}/send")
def send_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    from app.services.notification import NotificationService
    service = NotificationService(db)
    success = service.send_notification(notification_id)
    return {"success": success}


@router.post("/process-pending")
def process_pending_notifications(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    from app.services.notification import NotificationService
    service = NotificationService(db)
    service.process_pending_notifications()
    return {"ok": True}