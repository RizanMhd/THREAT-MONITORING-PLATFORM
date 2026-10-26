import hmac
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.rate_limit import login_limiter
from app.db.session import get_db
from app.models import Incident, Notification, User
from app.models.enums import UserRole
from app.schemas.user import (
    AssigneeResponse,
    LoginRequest,
    LoginResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.services.audit import record_audit
from app.services.auth import (
    create_access_token,
    decode_token,
    hash_password,
    password_fingerprint,
    validate_password,
    verify_password,
)


router = APIRouter(prefix="/auth", tags=["authentication"])
settings = get_settings()


def _client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_current_user(
    authorization: str = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header",
        )

    payload = decode_token(authorization[7:])
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.username == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    if not hmac.compare_digest(
        str(payload.get("pv", "")), password_fingerprint(user.password_hash)
    ):
        raise HTTPException(status_code=401, detail="Token is no longer valid")

    return user


def require_role(*allowed_roles: UserRole):
    def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_checker


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = _client_ip(request)
    rate_key = f"login:{client_ip}:{credentials.username.lower()}"
    if not login_limiter.allow(rate_key, settings.LOGIN_RATE_LIMIT_PER_MINUTE, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": "60"},
        )

    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        record_audit(db, credentials.username, "Failed login", ip_address=client_ip)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    token = create_access_token(user.username, user.role.value, user.password_hash)
    record_audit(
        db,
        user.username,
        "Logged in",
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    return {"token": token, "role": user.role, "username": user.username}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/assignees", response_model=List[AssigneeResponse])
def list_assignees(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            UserRole.SYSTEM_ADMIN,
            UserRole.SECURITY_ANALYST,
            UserRole.SECURITY_MANAGER,
        )
    ),
):
    users = (
        db.query(User)
        .filter(
            User.is_active.is_(True),
            User.role.in_(
                [
                    UserRole.SYSTEM_ADMIN,
                    UserRole.SECURITY_ANALYST,
                    UserRole.SECURITY_MANAGER,
                ]
            ),
        )
        .order_by(User.username)
        .all()
    )
    return [{"username": user.username, "role": user.role} for user in users]


@router.post("/users", response_model=UserResponse)
def create_user(
    user_data: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    try:
        validate_password(user_data.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        email=user_data.email,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(user)
    record_audit(
        db,
        current_user.username,
        f"Created user {user.username} with role {user.role.value}",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    return db.query(User).order_by(User.username).all()


@router.get("/users/{username}", response_model=UserResponse)
def get_user(
    username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != UserRole.SYSTEM_ADMIN and current_user.username != username:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/users/{username}", response_model=UserResponse)
def update_user(
    username: str,
    updates: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    is_admin = current_user.role == UserRole.SYSTEM_ADMIN
    is_self = current_user.username == username
    if not is_admin and not is_self:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    update_data = updates.model_dump(exclude_unset=True)
    if not is_admin:
        forbidden = {"role", "is_active"} & update_data.keys()
        if forbidden:
            raise HTTPException(
                status_code=403,
                detail="Only administrators can change roles or account status",
            )

    if "role" in update_data and update_data["role"] != user.role:
        _ensure_not_last_admin(db, user)
        user.role = update_data["role"]
    if "is_active" in update_data:
        if not update_data["is_active"]:
            _ensure_not_last_admin(db, user)
            if is_self:
                raise HTTPException(
                    status_code=400, detail="You cannot disable your own account"
                )
        user.is_active = bool(update_data["is_active"])
    if "email" in update_data:
        user.email = update_data["email"]
    if "password" in update_data and update_data["password"]:
        try:
            validate_password(update_data["password"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        user.password_hash = hash_password(update_data["password"])

    record_audit(
        db,
        current_user.username,
        f"Updated user {username}",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{username}")
def delete_user(
    username: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == current_user.username:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    _ensure_not_last_admin(db, user)

    assigned = db.query(Incident).filter(Incident.owner == username).count()
    if assigned:
        raise HTTPException(
            status_code=400,
            detail=f"User owns {assigned} incidents; deactivate the account instead",
        )

    db.query(Notification).filter(Notification.recipient == username).delete(
        synchronize_session=False
    )
    db.delete(user)
    record_audit(
        db,
        current_user.username,
        f"Deleted user {username}",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    return {"ok": True}


def _ensure_not_last_admin(db: Session, user: User) -> None:
    if user.role != UserRole.SYSTEM_ADMIN:
        return
    admin_count = (
        db.query(User)
        .filter(User.role == UserRole.SYSTEM_ADMIN, User.is_active.is_(True))
        .count()
    )
    if admin_count <= 1:
        raise HTTPException(
            status_code=400, detail="Cannot remove the last active administrator"
        )
