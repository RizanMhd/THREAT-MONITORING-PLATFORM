import csv
import io
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.time import utc_iso
from app.models import Event, Incident, InvestigationNote
from app.models.enums import IncidentStatus, SeverityLevel


OPEN_STATUSES = [
    IncidentStatus.NEW,
    IncidentStatus.ASSIGNED,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.ESCALATED,
]


def _utc_timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


class ReportingService:
    def __init__(self, db: Session):
        self.db = db

    def get_dashboard_stats(self) -> Dict[str, Any]:
        now = datetime.utcnow()
        day_ago = now - timedelta(hours=24)

        total_events = self.db.query(Event).count()
        total_incidents = self.db.query(Incident).count()
        open_incidents = self.db.query(Incident).filter(
            Incident.status.in_(OPEN_STATUSES)
        ).count()

        critical_high = self.db.query(Incident).filter(
            Incident.status.in_(OPEN_STATUSES),
            Incident.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH]),
        ).count()

        severity_counts = dict(
            self.db.query(Incident.severity, func.count(Incident.id))
            .filter(Incident.status.in_(OPEN_STATUSES))
            .group_by(Incident.severity)
            .all()
        )

        top_ips = (
            self.db.query(Event.ip, func.count(Event.id))
            .group_by(Event.ip)
            .order_by(desc(func.count(Event.id)))
            .limit(10)
            .all()
        )

        durations = self._resolution_durations()
        detection_times = self._detection_times()

        return {
            "total_events": total_events,
            "events_last_24h": self.db.query(Event)
            .filter(Event.ts >= time.time() - 86400)
            .count(),
            "total_incidents": total_incidents,
            "incidents_last_24h": self.db.query(Incident)
            .filter(Incident.created_at >= day_ago)
            .count(),
            "open_incidents": open_incidents,
            "unassigned_incidents": self.db.query(Incident)
            .filter(Incident.status.in_(OPEN_STATUSES), Incident.owner.is_(None))
            .count(),
            "critical_high_incidents": critical_high,
            "open_by_severity": {
                (key.value if hasattr(key, "value") else str(key)): value
                for key, value in severity_counts.items()
            },
            "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "avg_resolution_seconds": self._average(durations),
            "mttd_seconds": self._average(detection_times),
            "mttr_seconds": self._average(durations),
        }

    def _resolution_durations(self) -> List[float]:
        rows = (
            self.db.query(Incident.resolved_at, Incident.created_at)
            .filter(Incident.resolved_at.isnot(None), Incident.created_at.isnot(None))
            .all()
        )
        return [
            (resolved - created).total_seconds()
            for resolved, created in rows
            if resolved and created and resolved >= created
        ]

    def _detection_times(self) -> List[float]:
        rows = (
            self.db.query(Incident.created_at, Incident.first_event_ts)
            .filter(Incident.first_event_ts.isnot(None))
            .all()
        )
        values = []
        for created, first_event_ts in rows:
            if created and first_event_ts:
                delta = _utc_timestamp(created) - first_event_ts
                if delta >= 0:
                    values.append(delta)
        return values

    @staticmethod
    def _average(values: List[float]) -> Optional[float]:
        if not values:
            return None
        return round(sum(values) / len(values), 2)

    def get_incident_trends(self, days: int = 7) -> List[Dict[str, Any]]:
        days = min(max(days, 1), 365)
        cutoff = datetime.utcnow() - timedelta(days=days)
        incidents = (
            self.db.query(Incident.created_at, Incident.severity)
            .filter(Incident.created_at >= cutoff)
            .all()
        )

        grouped: Dict[tuple[str, str], int] = {}
        for created, severity in incidents:
            if not created:
                continue
            key = (created.date().isoformat(), severity.value.lower())
            grouped[key] = grouped.get(key, 0) + 1

        return [
            {"date": date, "severity": severity, "count": count}
            for (date, severity), count in sorted(grouped.items())
        ]

    def get_analyst_workload(self) -> List[Dict[str, Any]]:
        workload = (
            self.db.query(
                Incident.owner,
                func.count(Incident.id)
                .filter(Incident.status.in_(OPEN_STATUSES))
                .label("assigned"),
                func.count(Incident.id)
                .filter(Incident.status == IncidentStatus.RESOLVED)
                .label("resolved"),
            )
            .filter(Incident.owner.isnot(None))
            .group_by(Incident.owner)
            .all()
        )

        return [
            {
                "analyst": owner,
                "assigned_count": assigned or 0,
                "resolved_count": resolved or 0,
            }
            for owner, assigned, resolved in workload
        ]

    def generate_daily_summary(
        self, date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        date = date or datetime.utcnow()
        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return self._summary(start, end, start.date().isoformat())

    def generate_weekly_summary(
        self, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        end_date = end_date or datetime.utcnow()
        start = end_date - timedelta(days=7)
        return self._summary(start, end_date, f"{start.date()} to {end_date.date()}")

    def _summary(self, start: datetime, end: datetime, label: str) -> Dict[str, Any]:
        start_ts = _utc_timestamp(start)
        end_ts = _utc_timestamp(end)

        events = self.db.query(Event).filter(
            Event.ts >= start_ts, Event.ts < end_ts
        ).count()
        incident_query = self.db.query(Incident).filter(
            Incident.created_at >= start, Incident.created_at < end
        )
        incidents = incident_query.count()

        severity_counts = dict(
            self.db.query(Incident.severity, func.count(Incident.id))
            .filter(Incident.created_at >= start, Incident.created_at < end)
            .group_by(Incident.severity)
            .all()
        )

        top_threats = (
            self.db.query(Incident.title, Incident.severity, func.count(Incident.id))
            .filter(Incident.created_at >= start, Incident.created_at < end)
            .group_by(Incident.title, Incident.severity)
            .order_by(desc(func.count(Incident.id)))
            .limit(5)
            .all()
        )

        return {
            "date": label,
            "total_events": events,
            "total_incidents": incidents,
            "incidents_by_severity": {
                key.value.lower(): value for key, value in severity_counts.items()
            },
            "top_threats": [
                {"title": title, "severity": severity.value.lower(), "count": count}
                for title, severity, count in top_threats
            ],
        }

    def generate_incident_report(self, incident_id: int) -> Dict[str, Any]:
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return {}

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

        return {
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity.value.lower(),
                "status": incident.status.value.lower(),
                "owner": incident.owner,
                "risk_score": incident.risk_score,
                "ip": incident.ip,
                "created_at": utc_iso(incident.created_at),
                "resolved_at": utc_iso(incident.resolved_at),
                "count": incident.count,
            },
            "timeline": timeline,
        }

    def generate_trend_report(self, days: int = 30) -> Dict[str, Any]:
        return {"period_days": days, "trends": self.get_incident_trends(days)}

    def generate_performance_report(self) -> Dict[str, Any]:
        stats = self.get_dashboard_stats()
        return {
            "detection": {"mttd_seconds": stats.get("mttd_seconds")},
            "response": {
                "mttr_seconds": stats.get("mttr_seconds"),
                "avg_resolution_seconds": stats.get("avg_resolution_seconds"),
            },
            "analyst_performance": self.get_analyst_workload(),
        }

    def export_incidents_csv(self, incidents: List[Incident]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "ID",
                "Title",
                "Severity",
                "Status",
                "Owner",
                "Created",
                "Resolved",
                "Event Count",
                "IP",
                "Risk Score",
            ]
        )

        for incident in incidents:
            writer.writerow(
                [
                    incident.id,
                    incident.title,
                    incident.severity.value,
                    incident.status.value,
                    incident.owner or "Unassigned",
                    utc_iso(incident.created_at) or "",
                    utc_iso(incident.resolved_at) or "",
                    incident.count,
                    incident.ip or "",
                    round(incident.risk_score, 2) if incident.risk_score else "",
                ]
            )

        return output.getvalue()
