from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.session import get_db
from app.models import Incident, User
from app.models.enums import IncidentStatus, SeverityLevel, UserRole
from app.schemas.incident import (
    IncidentDetailResponse,
    IncidentResponse,
    IncidentUpdate,
    NoteCreate,
    ResolveRequest,
)
from app.services.incident_management import IncidentManagementService


router = APIRouter(prefix="/incidents", tags=["incidents"])

READ_ROLES = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
    UserRole.VIEWER,
)
WRITE_ROLES = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
)


@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[SeverityLevel] = None,
    owner: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    service = IncidentManagementService(db)
    return service.get_incidents(
        status=status,
        severity=severity,
        owner=owner,
        limit=limit,
        offset=offset,
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    service = IncidentManagementService(db)
    incident = service.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = service.get_incident_timeline(incident_id)
    events = service.get_incident_events(incident_id)
    return {
        **incident.__dict__,
        "timeline": timeline,
        "related_events": [
            {
                "id": event.id,
                "ts": event.ts,
                "ip": event.ip,
                "user": event.user,
                "event_type": event.event_type,
                "country": event.country,
                "detail": event.detail,
                "role": event.role,
                "source_id": event.source_id,
            }
            for event in events
        ],
    }


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    update_data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*WRITE_ROLES)),
):
    service = IncidentManagementService(db)
    try:
        incident = service.update_incident(incident_id, update_data, current_user.username)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{incident_id}/notes", response_model=dict)
def add_note(
    incident_id: int,
    payload: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*WRITE_ROLES)),
):
    service = IncidentManagementService(db)
    incident = service.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        note = service.add_note(incident_id, current_user.username, payload.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "note_id": note.id}


@router.post("/{incident_id}/escalate", response_model=IncidentResponse)
def escalate_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*WRITE_ROLES)),
):
    service = IncidentManagementService(db)
    try:
        incident = service.escalate_incident(incident_id, current_user.username)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
def resolve_incident(
    incident_id: int,
    payload: ResolveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*WRITE_ROLES)),
):
    service = IncidentManagementService(db)
    try:
        incident = service.resolve_incident(
            incident_id, current_user.username, payload.resolution_summary
        )
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{incident_id}/close", response_model=IncidentResponse)
def close_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(UserRole.SECURITY_MANAGER, UserRole.SYSTEM_ADMIN)
    ),
):
    service = IncidentManagementService(db)
    try:
        incident = service.close_incident(incident_id, current_user.username)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
