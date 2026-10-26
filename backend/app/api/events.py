import hmac
import random
import time
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.core.config import get_settings
from app.core.rate_limit import test_endpoint_limiter
from app.db.session import get_db
from app.models import Event, LogSource, User
from app.models.enums import UserRole
from app.schemas.event import EventBatchCreate, EventCreate, EventResponse
from app.services.correlation import CorrelationEngine
from app.services.detection import DetectionEngine
from app.services.normalization import NormalizationService


router = APIRouter(prefix="/events", tags=["events"])
settings = get_settings()

ANY_ROLE = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
    UserRole.VIEWER,
)


def verify_ingest_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.INGEST_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


def _ensure_source(db: Session, source_id: str, source_type: str = "generic") -> None:
    source = db.query(LogSource).filter(LogSource.id == source_id).first()
    if source:
        if not source.is_active:
            raise HTTPException(
                status_code=400,
                detail=f"Log source '{source_id}' is disabled",
            )
        return
    db.add(
        LogSource(
            id=source_id,
            name=source_id.replace("-", " ").title(),
            source_type=source_type,
            is_active=1,
        )
    )
    db.flush()


def _store_events(
    db: Session, events: List[EventCreate], source_type: str = "generic"
) -> Tuple[int, int, int]:
    detection_engine = DetectionEngine(db)
    correlation_engine = CorrelationEngine(db)
    accepted = 0
    new_incidents = 0
    alerts = 0

    for event_data in events:
        _ensure_source(db, event_data.source_id, source_type)
        db_event = Event(**event_data.model_dump())
        db.add(db_event)
        db.flush()

        hits = detection_engine.evaluate_event(db_event)
        if hits:
            alerts += len(hits)
            db_event.hit = 1
            new_incidents += len(correlation_engine.correlate_events(db_event, hits))
        accepted += 1

    db.commit()
    return accepted, new_incidents, alerts


@router.post("/ingest", response_model=dict)
def ingest_events(
    batch: EventBatchCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_ingest_key),
):
    if len(batch.events) > settings.MAX_INGEST_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"Batch exceeds {settings.MAX_INGEST_BATCH} events",
        )
    accepted, new_incidents, alerts = _store_events(db, batch.events)
    return {
        "accepted": accepted,
        "new_incidents": new_incidents,
        "alerts": alerts,
    }


@router.post("/ingest/raw", response_model=dict)
def ingest_raw_events(
    events: List[dict],
    source_type: str = "generic",
    source_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _: None = Depends(verify_ingest_key),
):
    if not events:
        raise HTTPException(status_code=400, detail="No events supplied")
    if len(events) > settings.MAX_INGEST_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"Batch exceeds {settings.MAX_INGEST_BATCH} events",
        )

    normalized = [
        NormalizationService.normalize(
            raw_event,
            source_type,
            source_id=source_id or f"{source_type}-raw",
        )
        for raw_event in events
    ]
    accepted, new_incidents, alerts = _store_events(db, normalized, source_type)
    return {
        "accepted": accepted,
        "new_incidents": new_incidents,
        "alerts": alerts,
    }


@router.get("", response_model=List[EventResponse])
def list_events(
    limit: int = 200,
    ip: Optional[str] = None,
    user: Optional[str] = None,
    event_type: Optional[str] = None,
    source_id: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    hit_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*ANY_ROLE)),
):
    query = db.query(Event).order_by(desc(Event.id))

    if ip:
        query = query.filter(Event.ip == ip)
    if user:
        query = query.filter(Event.user == user)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if source_id:
        query = query.filter(Event.source_id == source_id)
    if start_ts:
        query = query.filter(Event.ts >= start_ts)
    if end_ts:
        query = query.filter(Event.ts <= end_ts)
    if hit_only:
        query = query.filter(Event.hit == 1)

    return query.limit(min(max(limit, 1), 1000)).all()


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*ANY_ROLE)),
):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/simulate/{scenario}", response_model=dict)
def simulate_scenario(
    scenario: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    if not settings.ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Test endpoints are disabled")
    if not test_endpoint_limiter.allow(f"test:{current_user.username}", 30, 60):
        raise HTTPException(status_code=429, detail="Too many test runs")

    scenario = scenario.strip().lower()
    scenarios = {
        "brute_force": _scenario_brute_force,
        "port_scan": _scenario_port_scan,
        "request_flood": _scenario_request_flood,
        "new_country": _scenario_new_country,
        "admin_access": _scenario_admin_access,
        "bad_ip": _scenario_bad_ip,
        "config_change": _scenario_config_change,
        "normal": _scenario_normal,
    }
    if scenario == "all":
        total_accepted = total_new = total_alerts = 0
        for name, factory in scenarios.items():
            accepted, new_incidents, alerts = _store_events(db, factory())
            total_accepted += accepted
            total_new += new_incidents
            total_alerts += alerts
        return {
            "scenario": scenario,
            "accepted": total_accepted,
            "new_incidents": total_new,
            "alerts": total_alerts,
        }

    factory = scenarios.get(scenario)
    if not factory:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario. Choose one of: {', '.join(scenarios)}",
        )

    accepted, new_incidents, alerts = _store_events(db, factory())
    return {
        "scenario": scenario,
        "accepted": accepted,
        "new_incidents": new_incidents,
        "alerts": alerts,
    }


def _now() -> float:
    return time.time()


def _random_ip() -> str:
    return f"203.0.113.{random.randint(1, 250)}"


def _event(**kwargs) -> EventCreate:
    return EventCreate(source_id="simulator", **kwargs)


def _scenario_brute_force() -> List[EventCreate]:
    ip = _random_ip()
    now = _now()
    return [
        _event(
            ip=ip,
            user="admin",
            event_type="login_failed",
            country="RU",
            detail="Failed password",
            ts=now - (5 - index) * 0.2,
        )
        for index in range(6)
    ]


def _scenario_port_scan() -> List[EventCreate]:
    ip = _random_ip()
    now = _now()
    return [
        _event(
            ip=ip,
            user="-",
            event_type="port_probe",
            country="NL",
            detail=str(20 + index * 11),
            ts=now - (10 - index) * 0.1,
        )
        for index in range(10)
    ]


def _scenario_request_flood() -> List[EventCreate]:
    ip = _random_ip()
    now = _now()
    return [
        _event(
            ip=ip,
            user="-",
            event_type="http_request",
            country="CN",
            detail="/index",
            ts=now - (32 - index) * 0.05,
        )
        for index in range(32)
    ]


def _scenario_new_country() -> List[EventCreate]:
    return [
        _event(
            ip=_random_ip(),
            user=random.choice(["alice", "bob"]),
            event_type="login_success",
            country="BR",
            detail="OAuth login",
        )
    ]


def _scenario_admin_access() -> List[EventCreate]:
    return [
        _event(
            ip=_random_ip(),
            user="bob",
            role="staff",
            event_type="http_request",
            country="LK",
            detail="/admin/users",
        )
    ]


def _scenario_bad_ip() -> List[EventCreate]:
    return [
        _event(
            ip="185.220.101.7",
            user="-",
            event_type="http_request",
            country="RU",
            detail="/wp-login.php",
        )
    ]


def _scenario_config_change() -> List[EventCreate]:
    return [
        _event(
            ip=_random_ip(),
            user="bob",
            role="staff",
            event_type="security_group_modified",
            country="LK",
            detail="AuthorizeSecurityGroupIngress 0.0.0.0/0 port 22",
        )
    ]


def _scenario_normal() -> List[EventCreate]:
    events = []
    for _ in range(10):
        user = random.choice(["alice", "bob", "carol"])
        country = "SG" if user == "carol" else "LK"
        events.append(
            _event(
                ip=_random_ip(),
                user=user,
                role="staff",
                event_type=random.choice(["http_request", "login_success"]),
                country=country,
                detail=random.choice(["/home", "/profile", "/reports"]),
            )
        )
    return events
