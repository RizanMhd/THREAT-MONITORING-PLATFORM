import logging
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import DetectionRule, Event, Incident, IncidentEvent, InvestigationNote
from app.models.enums import IncidentStatus, NoteKind, SeverityLevel
from app.services.audit import record_audit
from app.services.notification import NotificationService
from app.services.scoring import RiskScoringService


logger = logging.getLogger(__name__)
settings = get_settings()

SEVERITY_RANK = {
    SeverityLevel.LOW: 0,
    SeverityLevel.MEDIUM: 1,
    SeverityLevel.HIGH: 2,
    SeverityLevel.CRITICAL: 3,
}


def _incident_severity(rule_severity: SeverityLevel, risk_score: float) -> SeverityLevel:
    classified = SeverityLevel(
        RiskScoringService.get_severity_classification(risk_score).upper()
    )
    if SEVERITY_RANK[classified] < SEVERITY_RANK[rule_severity]:
        return rule_severity
    return classified


class CorrelationEngine:
    def __init__(self, db: Session):
        self.db = db
        self.scoring_service = RiskScoringService()
        self.notification_service = NotificationService(db)

    def correlate_events(
        self, event: Event, rule_hits: List[Tuple[str, str]]
    ) -> List[Incident]:
        if not rule_hits:
            return []

        created_incidents: List[Incident] = []
        for rule_id, explanation in rule_hits:
            rule = self.db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
            if not rule:
                continue
            incident = self._create_or_update_incident(event, rule, explanation, rule_hits)
            if incident:
                created_incidents.append(incident)
        return created_incidents

    def _create_or_update_incident(
        self,
        event: Event,
        rule: DetectionRule,
        explanation: str,
        all_hits: List[Tuple[str, str]],
    ) -> Optional[Incident]:
        correlation_key = self._generate_correlation_key(event, rule.id)
        cutoff = datetime.utcnow() - timedelta(seconds=settings.DEDUPLICATION_WINDOW_SECONDS)

        existing = self.db.query(Incident).filter(
            Incident.key == correlation_key,
            Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED]),
            Incident.updated_at >= cutoff,
        ).order_by(Incident.updated_at.desc()).first()

        if existing:
            existing.count += 1
            existing.updated_at = datetime.utcnow()
            existing.last_event_ts = max(existing.last_event_ts or event.ts, event.ts)
            risk_score = self.scoring_service.calculate_risk_score(
                rule_id=rule.id,
                event=event,
                severity=rule.severity.value,
                asset_criticality=existing.asset_criticality or "medium",
                detection_confidence=existing.detection_confidence or 0.8,
                event_frequency=existing.count,
            )
            existing.risk_score = risk_score
            existing.severity = _incident_severity(rule.severity, risk_score)
            self._link_event_to_incident(existing.id, event.id)
            self.db.commit()
            return None

        risk_score = self.scoring_service.calculate_risk_score(
            rule_id=rule.id,
            event=event,
            severity=rule.severity.value,
            asset_criticality="medium",
            detection_confidence=0.8,
            event_frequency=len(all_hits),
        )
        severity = _incident_severity(rule.severity, risk_score)

        now = datetime.utcnow()
        incident = Incident(
            key=correlation_key,
            title=f"{rule.name} from {event.ip}",
            description=explanation,
            severity=severity,
            risk_score=risk_score,
            status=IncidentStatus.NEW,
            ip=event.ip,
            asset_criticality="medium",
            detection_confidence=0.8,
            potential_impact="medium",
            count=1,
            first_event_ts=event.ts,
            last_event_ts=event.ts,
            created_at=now,
            updated_at=now,
        )

        self.db.add(incident)
        self.db.flush()
        self._link_event_to_incident(incident.id, event.id)

        self.db.add(
            InvestigationNote(
                incident_id=incident.id,
                author="system",
                kind=NoteKind.SYSTEM,
                text=f"Incident auto-created by rule {rule.id}: {explanation}",
            )
        )
        record_audit(
            self.db,
            "system",
            f"Auto-created incident {incident.id} from rule {rule.id}",
        )
        self.db.commit()
        self.db.refresh(incident)

        try:
            self.notification_service.notify_new_incident(incident)
        except Exception:
            logger.exception("Failed to create notifications for incident %s", incident.id)

        return incident

    def _generate_correlation_key(self, event: Event, rule_id: str) -> str:
        if rule_id in ("R2", "R5"):
            return f"{rule_id}:{event.ip}:{event.user or '-'}"
        return f"{rule_id}:{event.ip}"

    def _link_event_to_incident(self, incident_id: int, event_id: int) -> None:
        self.db.add(IncidentEvent(incident_id=incident_id, event_id=event_id))
