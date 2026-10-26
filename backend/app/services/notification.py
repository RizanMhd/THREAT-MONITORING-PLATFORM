import logging
import smtplib
from datetime import datetime
from email.message import EmailMessage
from typing import List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Incident, Notification, User
from app.models.enums import (
    NotificationChannel,
    NotificationStatus,
    SeverityLevel,
    UserRole,
)


logger = logging.getLogger(__name__)
settings = get_settings()


class NotificationService:
    def __init__(self, db: Session):
        self.db = db

    def create_notification(
        self,
        recipient: str,
        channel: NotificationChannel,
        subject: str,
        message: str,
        incident_id: Optional[int] = None,
    ) -> Notification:
        in_app = channel == NotificationChannel.IN_APP
        notification = Notification(
            incident_id=incident_id,
            recipient=recipient,
            channel=channel,
            subject=subject,
            message=message,
            status=NotificationStatus.SENT if in_app else NotificationStatus.PENDING,
            sent_at=datetime.utcnow() if in_app else None,
        )
        self.db.add(notification)
        self.db.commit()
        self.db.refresh(notification)
        return notification

    def send_notification(self, notification_id: int) -> bool:
        notification = self.db.query(Notification).filter(
            Notification.id == notification_id
        ).first()
        if not notification:
            return False

        try:
            if notification.channel == NotificationChannel.EMAIL:
                self._send_email(notification)
            elif notification.channel == NotificationChannel.SNS:
                self._send_sns(notification)
            notification.status = NotificationStatus.SENT
            notification.sent_at = datetime.utcnow()
        except Exception as exc:
            notification.status = NotificationStatus.FAILED
            notification.error_message = str(exc)
        finally:
            self.db.commit()

        return notification.status == NotificationStatus.SENT

    def _recipient_email(self, username: str) -> str:
        user = self.db.query(User).filter(User.username == username).first()
        if not user or not user.email:
            raise RuntimeError(f"No email address configured for {username}")
        return user.email

    def _send_email(self, notification: Notification) -> None:
        if not settings.SMTP_HOST:
            raise RuntimeError("SMTP is not configured")

        msg = EmailMessage()
        msg["Subject"] = notification.subject or "SecureWatch notification"
        msg["From"] = settings.MAIL_FROM
        msg["To"] = self._recipient_email(notification.recipient)
        msg.set_content(notification.message)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            if settings.SMTP_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASS:
                server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.send_message(msg)

    def _send_sns(self, notification: Notification) -> None:
        raise RuntimeError("SNS delivery is not configured")

    def notify_new_incident(self, incident: Incident) -> None:
        for recipient in self._get_recipients_for_severity(incident.severity):
            self.create_notification(
                recipient=recipient,
                channel=NotificationChannel.IN_APP,
                subject=f"New {incident.severity.value} incident: {incident.title}",
                message=f"Incident {incident.id} created: {incident.description}",
                incident_id=incident.id,
            )
            if settings.SMTP_HOST and incident.severity in (
                SeverityLevel.HIGH,
                SeverityLevel.CRITICAL,
            ):
                self.create_notification(
                    recipient=recipient,
                    channel=NotificationChannel.EMAIL,
                    subject=f"[{incident.severity.value}] {incident.title}",
                    message=(
                        f"Incident {incident.id}: {incident.description}\n"
                        f"IP: {incident.ip}\nTime: {incident.created_at}"
                    ),
                    incident_id=incident.id,
                )

    def notify_high_severity(self, incident: Incident) -> None:
        self.notify_new_incident(incident)

    def notify_escalation(self, incident: Incident) -> None:
        recipients = self._get_recipients_for_severity(SeverityLevel.HIGH)
        for recipient in recipients:
            self.create_notification(
                recipient=recipient,
                channel=NotificationChannel.IN_APP,
                subject=f"Escalated: {incident.title}",
                message=f"Incident {incident.id} has been escalated.",
                incident_id=incident.id,
            )

    def notify_assignment(self, incident: Incident, assignee: str) -> None:
        self.create_notification(
            recipient=assignee,
            channel=NotificationChannel.IN_APP,
            subject=f"Incident assigned: {incident.title}",
            message=f"Incident {incident.id} was assigned to you.",
            incident_id=incident.id,
        )

    def get_user_notifications(self, username: str, limit: int = 50) -> List[Notification]:
        return self.db.query(Notification).filter(
            Notification.recipient == username
        ).order_by(desc(Notification.created_at)).limit(limit).all()

    def _get_recipients_for_severity(self, severity: SeverityLevel) -> List[str]:
        if severity == SeverityLevel.CRITICAL:
            roles = [
                UserRole.SECURITY_ANALYST,
                UserRole.SECURITY_MANAGER,
                UserRole.SYSTEM_ADMIN,
            ]
        elif severity == SeverityLevel.HIGH:
            roles = [UserRole.SECURITY_ANALYST, UserRole.SECURITY_MANAGER]
        else:
            roles = [UserRole.SECURITY_ANALYST]

        users = self.db.query(User).filter(
            User.role.in_(roles), User.is_active.is_(True)
        ).all()
        return [user.username for user in users]

    def process_pending_notifications(self) -> None:
        pending = self.db.query(Notification).filter(
            Notification.status == NotificationStatus.PENDING
        ).all()
        for notification in pending:
            self.send_notification(notification.id)
