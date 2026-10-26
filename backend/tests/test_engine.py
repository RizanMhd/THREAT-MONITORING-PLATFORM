import pytest
import tempfile
import os
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["INGEST_KEY"] = "test-ingest-key"
os.environ["TESTING"] = "1"

from app.db.session import Base
from app.models import Event, DetectionRule
from app.models.enums import SeverityLevel
from app.services.detection import DetectionEngine


@pytest.fixture
def db_session():
    db_file = tempfile.mktemp(suffix='.db')
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    engine = create_engine(os.environ["DATABASE_URL"])
    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    default_rules = [
        DetectionRule(id="R1", name="Brute-force login", description="", condition="", severity=SeverityLevel.HIGH, enabled=1, threshold=5, time_window_seconds=120, created_at="2024-01-01"),
        DetectionRule(id="R2", name="Suspicious login location", description="", condition="", severity=SeverityLevel.MEDIUM, enabled=1, created_at="2024-01-01"),
        DetectionRule(id="R3", name="Request flood", description="", condition="", severity=SeverityLevel.HIGH, enabled=1, threshold=30, time_window_seconds=60, created_at="2024-01-01"),
        DetectionRule(id="R4", name="Port scan", description="", condition="", severity=SeverityLevel.MEDIUM, enabled=1, threshold=8, time_window_seconds=60, created_at="2024-01-01"),
        DetectionRule(id="R5", name="Privilege abuse", description="", condition="", severity=SeverityLevel.CRITICAL, enabled=1, created_at="2024-01-01"),
        DetectionRule(id="R6", name="Known malicious IP", description="", condition="", severity=SeverityLevel.CRITICAL, enabled=1, created_at="2024-01-01"),
        DetectionRule(id="R7", name="Unauthorized config change", description="", condition="", severity=SeverityLevel.HIGH, enabled=1, created_at="2024-01-01"),
    ]
    for rule in default_rules:
        db.merge(rule)
    db.commit()

    yield db

    db.close()
    engine.dispose()
    try:
        os.unlink(db_file)
    except PermissionError:
        pass


def add_event(db, **k):
    defaults = {
        "ts": time.time(),
        "source_id": "test",
        "ip": "1.2.3.4",
        "user": "-",
        "event_type": "x",
        "country": "-",
        "detail": "",
        "role": None,
    }
    defaults.update(k)
    e = Event(**defaults)
    db.add(e)
    db.flush()
    return e


def get_hits(hits):
    return [h[0] for h in hits]


def test_bruteforce_needs_five(db_session):
    db = db_session
    db.query(Event).delete()
    db.commit()
    for _ in range(4):
        e = add_event(db, event_type="login_failed")
    engine = DetectionEngine(db)
    assert "R1" not in get_hits(engine.evaluate_event(e))
    e = add_event(db, event_type="login_failed")
    assert "R1" in get_hits(engine.evaluate_event(e))


def test_new_country(db_session):
    db = db_session
    db.query(Event).delete()
    db.commit()
    e = add_event(db, event_type="login_success", user="alice", country="BR")
    engine = DetectionEngine(db)
    assert "R2" in get_hits(engine.evaluate_event(e))
    e = add_event(db, event_type="login_success", user="alice", country="LK")
    assert "R2" not in get_hits(engine.evaluate_event(e))


def test_port_scan(db_session):
    db = db_session
    db.query(Event).delete()
    db.commit()
    for p in range(8):
        e = add_event(db, event_type="port_probe", detail=str(p))
    engine = DetectionEngine(db)
    assert "R4" in get_hits(engine.evaluate_event(e))


def test_privilege_abuse(db_session):
    db = db_session
    db.query(Event).delete()
    db.commit()
    e = add_event(db, event_type="http_request", user="bob", role="staff", detail="/admin/users")
    engine = DetectionEngine(db)
    assert "R5" in get_hits(engine.evaluate_event(e))


def test_blocklist(db_session):
    db = db_session
    db.query(Event).delete()
    db.commit()
    e = add_event(db, ip="185.220.101.7", event_type="http_request")
    engine = DetectionEngine(db)
    assert "R6" in get_hits(engine.evaluate_event(e))