from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.session import get_db
from app.models import Event, LogSource
from app.models.enums import UserRole
from app.schemas.log_source import (
    LogSourceCreate,
    LogSourceResponse,
    LogSourceUpdate,
)
from app.services.audit import record_audit


router = APIRouter(prefix="/log-sources", tags=["log sources"])

READ_ROLES = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
)


@router.get("", response_model=List[LogSourceResponse])
def list_log_sources(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*READ_ROLES)),
):
    return db.query(LogSource).order_by(LogSource.id).all()


@router.post("", response_model=LogSourceResponse)
def create_log_source(
    source_data: LogSourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    existing = db.query(LogSource).filter(LogSource.id == source_data.id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Log source ID already exists")

    source = LogSource(**source_data.model_dump())
    db.add(source)
    record_audit(
        db,
        current_user.username,
        f"Created log source {source.id}",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(source)
    return source


@router.get("/{source_id}", response_model=LogSourceResponse)
def get_log_source(
    source_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*READ_ROLES)),
):
    source = db.query(LogSource).filter(LogSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Log source not found")
    return source


@router.patch("/{source_id}", response_model=LogSourceResponse)
def update_log_source(
    source_id: str,
    updates: LogSourceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    source = db.query(LogSource).filter(LogSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Log source not found")

    update_dict = updates.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        if key == "is_active":
            setattr(source, key, 1 if value else 0)
        else:
            setattr(source, key, value)

    record_audit(
        db,
        current_user.username,
        f"Updated log source {source_id}",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(source)
    return source


@router.delete("/{source_id}")
def delete_log_source(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    source = db.query(LogSource).filter(LogSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Log source not found")

    event_count = db.query(Event).filter(Event.source_id == source_id).count()
    if event_count:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete a source with {event_count} events; deactivate it instead",
        )

    db.delete(source)
    record_audit(
        db,
        current_user.username,
        f"Deleted log source {source_id}",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return {"ok": True}
