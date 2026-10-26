import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import LogSource, User
from app.models.enums import UserRole
from app.services.auth import hash_password
from app.services.detection import DetectionEngine


logger = logging.getLogger(__name__)
settings = get_settings()

DEFAULT_LOG_SOURCES = [
    ("api", "Generic API ingestion", "generic"),
    ("simulator", "Built-in test generator", "test"),
    ("ssh-auth", "Linux SSH authentication log", "ssh"),
    ("windows-security", "Windows Security event log", "windows"),
    ("web-server", "Nginx or Apache access log", "web"),
    ("firewall", "Firewall or IDS feed", "firewall"),
    ("cloudtrail", "AWS CloudTrail", "aws"),
    ("cloudwatch", "AWS CloudWatch", "aws"),
    ("ids", "IDS/IPS alert feed", "ids"),
]

DEMO_USERS = [
    ("analyst", "analyst123", UserRole.SECURITY_ANALYST, "analyst@example.com"),
    ("manager", "manager123", UserRole.SECURITY_MANAGER, "manager@example.com"),
    ("viewer", "viewer123", UserRole.VIEWER, "viewer@example.com"),
]


def ensure_log_sources(db: Session) -> None:
    existing = {source_id for (source_id,) in db.query(LogSource.id).all()}
    for source_id, name, source_type in DEFAULT_LOG_SOURCES:
        if source_id not in existing:
            db.add(LogSource(id=source_id, name=name, source_type=source_type, is_active=1))
    db.commit()


def ensure_detection_rules(db: Session) -> None:
    DetectionEngine(db).initialize_default_rules()


def ensure_users(db: Session) -> None:
    user_count = db.query(User).count()
    active_admins = (
        db.query(User)
        .filter(User.role == UserRole.SYSTEM_ADMIN, User.is_active.is_(True))
        .count()
    )

    if active_admins == 0:
        admin = db.query(User).filter(
            User.username == settings.BOOTSTRAP_ADMIN_USERNAME
        ).first()
        admin_password = settings.BOOTSTRAP_ADMIN_PASSWORD
        if not admin_password:
            if settings.is_production:
                raise RuntimeError(
                    "No active administrator exists. "
                    "Set BOOTSTRAP_ADMIN_PASSWORD to create or recover the first admin."
                )
            admin_password = "admin123"
            if admin:
                logger.warning(
                    "No active administrator exists. Recovered development admin '%s' "
                    "with the default password. Change it before exposing this server.",
                    settings.BOOTSTRAP_ADMIN_USERNAME,
                )
            else:
                logger.warning(
                    "No users exist. Created development admin '%s' with the default password. "
                    "Change it before exposing this server.",
                    settings.BOOTSTRAP_ADMIN_USERNAME,
                )

        if admin:
            admin.role = UserRole.SYSTEM_ADMIN
            admin.is_active = True
            if settings.BOOTSTRAP_ADMIN_PASSWORD:
                admin.password_hash = hash_password(admin_password)
        else:
            db.add(
                User(
                    username=settings.BOOTSTRAP_ADMIN_USERNAME,
                    password_hash=hash_password(admin_password),
                    role=UserRole.SYSTEM_ADMIN,
                    email=settings.BOOTSTRAP_ADMIN_EMAIL,
                    is_active=True,
                    created_at=datetime.utcnow(),
                )
            )
        db.flush()

    if user_count == 0 and settings.BOOTSTRAP_DEMO_USERS and not settings.is_production:
        for username, password, role, email in DEMO_USERS:
            if username == settings.BOOTSTRAP_ADMIN_USERNAME:
                continue
            db.add(
                User(
                    username=username,
                    password_hash=hash_password(password),
                    role=role,
                    email=email,
                    is_active=True,
                    created_at=datetime.utcnow(),
                )
            )
        logger.warning(
            "Created demo accounts analyst/analyst123, manager/manager123, viewer/viewer123. "
            "Disable BOOTSTRAP_DEMO_USERS in production."
        )
    db.commit()


def seed_all(db: Session) -> None:
    ensure_log_sources(db)
    ensure_detection_rules(db)
    ensure_users(db)
