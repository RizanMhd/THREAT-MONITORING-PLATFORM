from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.time import utc_iso
from app.models import (
    Event,
    Incident,
    IncidentEvent,
    InvestigationNote,
    User,
)
from app.models.enums import IncidentStatus, NoteKind, SeverityLevel
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services.audit import record_audit
from app.services.notification import NotificationService


settings = get_settings()

VALID_STATUS_TRANSITIONS = {
    IncidentStatus.NEW: [IncidentStatus.ASSIGNED, IncidentStatus.INVESTIGATING],
    IncidentStatus.ASSIGNED: [IncidentStatus.INVESTIGATING, IncidentStatus.ESCALATED],
    IncidentStatus.INVESTIGATING: [IncidentStatus.ESCALATED, IncidentStatus.RESOLVED],
    IncidentStatus.ESCALATED: [IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED],
    IncidentStatus.RESOLVED: [IncidentStatus.CLOSED],
    IncidentStatus.CLOSED: [],
}


class IncidentManagementService:
    def __init__(self, db: Session):
        self.db = db
        self.notification_service = NotificationService(db)

    def create_incident(
        self,
        incident_data: IncidentCreate,
        created_by: str = "system",
    ) -> Incident:
        incident = Incident(**incident_data.model_dump())
        self.db.add(incident)
        self.db.flush()

        self._add_note(
            incident.id,
            "system",
            NoteKind.SYSTEM,
            f"Incident created: {incident.title}",
        )
        self._audit_log(created_by, f"Created incident {incident.id}: {incident.title}")

        if incident.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            self.notification_service.notify_high_severity(incident)

        self.db.commit()
        self.db.refresh(incident)
        return incident

    def get_incident(self, incident_id: int) -> Optional[Incident]:
        return self.db.query(Incident).filter(Incident.id == incident_id).first()

    def get_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[SeverityLevel] = None,
        owner: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Incident]:
        query = self.db.query(Incident)
        if status:
            query = query.filter(Incident.status == status)
        if severity:
            query = query.filter(Incident.severity == severity)
        if owner:
            query = query.filter(Incident.owner == owner)
        return (
            query.order_by(desc(Incident.created_at))
            .offset(max(offset, 0))
            .limit(min(max(limit, 1), 1000))
            .all()
        )

    def update_incident(
        self,
        incident_id: int,
        update_data: IncidentUpdate,
        updated_by: str,
    ) -> Optional[Incident]:
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        update_dict = update_data.model_dump(exclude_unset=True)

        if "status" in update_dict:
            new_status = update_dict["status"]
            if new_status == incident.status:
                raise ValueError("Incident already has that status")
            if new_status not in VALID_STATUS_TRANSITIONS.get(incident.status, []):
                raise ValueError(
                    f"Invalid status transition from {incident.status.value} to {new_status.value}"
                )

            incident.status = new_status
            incident.updated_at = datetime.utcnow()
            if new_status == IncidentStatus.RESOLVED:
                incident.resolved_at = datetime.utcnow()
            elif new_status == IncidentStatus.CLOSED:
                incident.closed_at = datetime.utcnow()

            self._add_note(
                incident_id,
                updated_by,
                NoteKind.EVENT,
                f"Status changed to {new_status.value}",
            )

        if "owner" in update_dict:
            owner = update_dict["owner"]
            if owner in (None, "", "Unassigned"):
                incident.owner = None
            else:
                assignee = self.db.query(User).filter(User.username == owner).first()
                if not assignee or not assignee.is_active:
                    raise ValueError("Assigned user does not exist or is inactive")
                incident.owner = owner
                if incident.status == IncidentStatus.NEW:
                    incident.status = IncidentStatus.ASSIGNED
                self.notification_service.notify_assignment(incident, owner)
            incident.updated_at = datetime.utcnow()
            self._add_note(
                incident_id,
                updated_by,
                NoteKind.EVENT,
                f"Assigned to {owner or 'Unassigned'}",
            )

        if "severity" in update_dict:
            old_severity = incident.severity
            incident.severity = update_dict["severity"]
            incident.updated_at = datetime.utcnow()
            self._add_note(
                incident_id,
                updated_by,
                NoteKind.EVENT,
                f"Severity changed from {old_severity.value} to {incident.severity.value}",
            )

        for field in ["risk_score", "asset_criticality", "detection_confidence", "potential_impact"]:
            if field in update_dict:
                setattr(incident, field, update_dict[field])

        self._audit_log(updated_by, f"Updated incident {incident_id}")
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def add_note(
        self,
        incident_id: int,
        author: str,
        text: str,
        kind: NoteKind = NoteKind.NOTE,
    ) -> InvestigationNote:
        if not text or not text.strip():
            raise ValueError("Note text is required")
        if len(text) > 4000:
            raise ValueError("Note text must be at most 4000 characters")
        return self._add_note(incident_id, author, kind, text.strip())

    def _add_note(
        self,
        incident_id: int,
        author: str,
        kind: NoteKind,
        text: str,
    ) -> InvestigationNote:
        note = InvestigationNote(
            incident_id=incident_id,
            author=author,
            kind=kind,
            text=text,
        )
        self.db.add(note)
        self.db.commit()
        return note

    def get_incident_timeline(self, incident_id: int) -> List[Dict[str, Any]]:
        incident = self.get_incident(incident_id)
        if not incident:
            return []

        timeline = []
        for note in incident.notes:
            timeline.append(
                {
                    "timestamp": utc_iso(note.created_at),
                    "author": note.author,
                    "kind": note.kind.value,
                    "text": note.text,
                }
            )
        return sorted(timeline, key=lambda item: item["timestamp"])

    def get_incident_events(self, incident_id: int) -> List[Event]:
        return (
            self.db.query(Event)
            .join(IncidentEvent, IncidentEvent.event_id == Event.id)
            .filter(IncidentEvent.incident_id == incident_id)
            .order_by(desc(Event.ts))
            .limit(200)
            .all()
        )

    def escalate_incident(self, incident_id: int, escalated_by: str) -> Optional[Incident]:
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        if incident.status not in (
            IncidentStatus.NEW,
            IncidentStatus.ASSIGNED,
            IncidentStatus.INVESTIGATING,
        ):
            raise ValueError(f"Cannot escalate incident in status {incident.status.value}")

        incident.status = IncidentStatus.ESCALATED
        incident.updated_at = datetime.utcnow()
        self._add_note(
            incident_id,
            escalated_by,
            NoteKind.EVENT,
            f"Escalated by {escalated_by}",
        )
        self._audit_log(escalated_by, f"Escalated incident {incident_id}")
        self.notification_service.notify_escalation(incident)

        self.db.commit()
        self.db.refresh(incident)
        return incident

    def resolve_incident(
        self,
        incident_id: int,
        resolved_by: str,
        resolution_summary: str,
    ) -> Optional[Incident]:
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        if incident.status not in (
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ESCALATED,
            IncidentStatus.ASSIGNED,
        ):
            raise ValueError(f"Cannot resolve incident in status {incident.status.value}")

        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = datetime.utcnow()
        incident.updated_at = datetime.utcnow()
        self._add_note(
            incident_id,
            resolved_by,
            NoteKind.NOTE,
            f"Resolved: {resolution_summary}",
        )
        self._audit_log(
            resolved_by,
            f"Resolved incident {incident_id}: {resolution_summary}",
        )

        self.db.commit()
        self.db.refresh(incident)
        return incident

    def close_incident(self, incident_id: int, closed_by: str) -> Optional[Incident]:
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        if incident.status != IncidentStatus.RESOLVED:
            raise ValueError(
                f"Can only close resolved incidents, current status: {incident.status.value}"
            )

        incident.status = IncidentStatus.CLOSED
        incident.closed_at = datetime.utcnow()
        incident.updated_at = datetime.utcnow()
        self._add_note(incident_id, closed_by, NoteKind.EVENT, f"Closed by {closed_by}")
        self._audit_log(closed_by, f"Closed incident {incident_id}")

        self.db.commit()
        self.db.refresh(incident)
        return incident

    def _audit_log(self, user: str, action: str) -> None:
        record_audit(self.db, user, action)
