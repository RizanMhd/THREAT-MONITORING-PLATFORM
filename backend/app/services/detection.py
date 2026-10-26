from typing import List, Tuple

from sqlalchemy.orm import Session

from app.core.time import utc_iso, utc_now
from app.models import DetectionRule, Event
from app.models.enums import SeverityLevel


BAD_IPS = {"185.220.101.7", "45.155.205.233", "91.240.118.50"}
USER_HOME_COUNTRIES = {"alice": "LK", "bob": "LK", "carol": "SG"}
CONFIG_CHANGE_EVENTS = (
    "security_group_modified",
    "policy_attached",
    "policy_detached",
    "user_created",
    "user_deleted",
    "access_key_created",
    "access_key_deleted",
)

DEFAULT_RULES = [
    {
        "id": "R1",
        "name": "Brute-force login",
        "description": "5 or more failed logins from one IP within 120 seconds",
        "condition": "event_type == 'login_failed' AND count(ip, 'login_failed', 120) >= 5",
        "severity": SeverityLevel.HIGH,
        "threshold": 5,
        "time_window_seconds": 120,
    },
    {
        "id": "R2",
        "name": "Suspicious login location",
        "description": "Successful login from a country that is not the user's usual country",
        "condition": "event_type == 'login_success' AND event.country != user.home_country",
        "severity": SeverityLevel.MEDIUM,
        "threshold": None,
        "time_window_seconds": None,
    },
    {
        "id": "R3",
        "name": "Request flood",
        "description": "30 or more HTTP requests from one IP within 60 seconds",
        "condition": "event_type == 'http_request' AND count(ip, 'http_request', 60) >= 30",
        "severity": SeverityLevel.HIGH,
        "threshold": 30,
        "time_window_seconds": 60,
    },
    {
        "id": "R4",
        "name": "Port scan",
        "description": "8 or more distinct ports probed by one IP within 60 seconds",
        "condition": "event_type == 'port_probe' AND count_distinct(ip, 'port_probe', 60) >= 8",
        "severity": SeverityLevel.MEDIUM,
        "threshold": 8,
        "time_window_seconds": 60,
    },
    {
        "id": "R5",
        "name": "Privilege abuse",
        "description": "A non-admin user requests an /admin path",
        "condition": "event_type == 'http_request' AND detail.startswith('/admin') AND role != 'admin'",
        "severity": SeverityLevel.CRITICAL,
        "threshold": None,
        "time_window_seconds": None,
    },
    {
        "id": "R6",
        "name": "Known malicious IP",
        "description": "Source IP is on the threat-intelligence blocklist",
        "condition": "ip IN threat_intelligence.blocklist",
        "severity": SeverityLevel.CRITICAL,
        "threshold": None,
        "time_window_seconds": None,
    },
    {
        "id": "R7",
        "name": "Unauthorized configuration change",
        "description": "Security-relevant cloud/IAM configuration change by a non-admin user",
        "condition": "event_type IN configuration_change_events AND user NOT IN ('admin', 'root', 'system')",
        "severity": SeverityLevel.HIGH,
        "threshold": None,
        "time_window_seconds": None,
    },
]


class DetectionEngine:
    def __init__(self, db: Session):
        self.db = db

    def get_active_rules(self) -> List[DetectionRule]:
        return self.db.query(DetectionRule).filter(DetectionRule.enabled == 1).all()

    def evaluate_event(self, event: Event) -> List[Tuple[str, str]]:
        hits: List[Tuple[str, str]] = []
        ip = event.ip
        event_type = (event.event_type or "").lower()
        ts = event.ts
        user = event.user or "-"
        country = (event.country or "-").upper()
        detail = event.detail or ""
        role = event.role

        rules = {rule.id: rule for rule in self.get_active_rules()}

        if "R6" in rules and ip in BAD_IPS:
            hits.append(("R6", f"Traffic from blocklisted IP {ip}"))

        if "R1" in rules and event_type == "login_failed":
            threshold = rules["R1"].threshold or 5
            window = rules["R1"].time_window_seconds or 120
            count = self._count_events(ip, "login_failed", ts - window)
            if count >= threshold:
                hits.append(("R1", f"{count} failed logins in {window} seconds from {ip}"))

        if "R2" in rules and event_type == "login_success":
            home = USER_HOME_COUNTRIES.get(user)
            if home and country and home.upper() != country:
                hits.append(("R2", f"{user} logged in from {country} (usual: {home})"))

        if "R3" in rules and event_type == "http_request":
            threshold = rules["R3"].threshold or 30
            window = rules["R3"].time_window_seconds or 60
            count = self._count_events(ip, "http_request", ts - window)
            if count >= threshold:
                hits.append(("R3", f"{count} HTTP requests in {window} seconds from {ip}"))

        if "R4" in rules and event_type == "port_probe":
            threshold = rules["R4"].threshold or 8
            window = rules["R4"].time_window_seconds or 60
            distinct_ports = self._count_distinct_details(ip, "port_probe", ts - window)
            if distinct_ports >= threshold:
                hits.append(("R4", f"{distinct_ports} distinct ports probed in {window} seconds from {ip}"))

        if "R5" in rules and event_type == "http_request":
            if detail.startswith("/admin") and role and role.lower() != "admin":
                hits.append(("R5", f"{user} ({role}) requested admin path {detail}"))

        if "R7" in rules and event_type in CONFIG_CHANGE_EVENTS:
            if user.lower() not in ("admin", "root", "system", "-"):
                hits.append(("R7", f"Unauthorized configuration change by {user}: {event_type}"))

        return hits

    def _count_events(self, ip: str, event_type: str, since: float) -> int:
        return self.db.query(Event).filter(
            Event.ip == ip,
            Event.event_type == event_type,
            Event.ts >= since,
        ).count()

    def _count_distinct_details(self, ip: str, event_type: str, since: float) -> int:
        return self.db.query(Event.detail).filter(
            Event.ip == ip,
            Event.event_type == event_type,
            Event.ts >= since,
        ).distinct().count()

    def initialize_default_rules(self) -> None:
        now = utc_iso(utc_now())
        for rule_data in DEFAULT_RULES:
            existing = self.db.query(DetectionRule).filter(
                DetectionRule.id == rule_data["id"]
            ).first()
            if existing:
                continue

            self.db.add(
                DetectionRule(
                    **rule_data,
                    enabled=1,
                    created_at=now,
                )
            )
        self.db.commit()
