import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

import pytest

_TEMP_DIR = tempfile.mkdtemp(prefix="securewatch-tests-")
_TEST_DB = Path(_TEMP_DIR) / "securewatch-test.db"

os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["INGEST_KEY"] = "test-ingest-key"
os.environ["TESTING"] = "1"
os.environ["ENVIRONMENT"] = "development"
os.environ["LOGIN_RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["BOOTSTRAP_DEMO_USERS"] = "true"
os.environ["ENABLE_TEST_ENDPOINTS"] = "true"

from fastapi.testclient import TestClient  # noqa: E402

from app.core.seed import seed_all  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.detection import DetectionEngine  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        db = SessionLocal()
        try:
            seed_all(db)
        finally:
            db.close()
        yield test_client
    engine.dispose()
    shutil.rmtree(_TEMP_DIR, ignore_errors=True)


def login(client, username, password):
    response = client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture(scope="module")
def headers(client):
    return {
        "admin": login(client, "admin", "admin123"),
        "analyst": login(client, "analyst", "analyst123"),
        "manager": login(client, "manager", "manager123"),
        "viewer": login(client, "viewer", "viewer123"),
    }


def unique_ip(prefix="198.51.100"):
    return f"{prefix}.{uuid.uuid4().int % 250 + 1}"


def ingest(client, ip, event_type="login_failed", count=6, user="admin", source="pytest-ingest"):
    now = time.time()
    events = [
        {
            "source_id": source,
            "ip": ip,
            "user": user,
            "event_type": event_type,
            "country": "RU",
            "detail": f"test event {index}",
            "ts": now - (count - index) * 0.1,
        }
        for index in range(count)
    ]
    return client.post(
        "/events/ingest",
        json={"events": events},
        headers={"X-API-Key": "test-ingest-key"},
    )


def test_health_and_auth(client, headers):
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"
    assert health.json()["test_endpoints"] is True
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").status_code == 200

    me = client.get("/auth/me", headers=headers["admin"])
    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert me.json()["role"] == "SYSTEM_ADMIN"

    assert client.get("/auth/me").status_code == 401
    assert client.post("/auth/login", json={"username": "admin", "password": "bad"}).status_code == 401
    assert client.get("/auth/assignees", headers=headers["viewer"]).status_code == 403
    assert len(client.get("/auth/assignees", headers=headers["analyst"]).json()) >= 3


def test_ingestion_detection_and_incident_workflow(client, headers):
    wrong = client.post(
        "/events/ingest",
        json={"events": [{"source_id": "x", "ip": "1.1.1.1", "event_type": "login_failed"}]},
        headers={"X-API-Key": "wrong"},
    )
    assert wrong.status_code == 401

    ip = unique_ip()
    response = ingest(client, ip)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 6
    assert body["new_incidents"] == 1
    assert body["alerts"] == 2

    events = client.get(f"/events?ip={ip}", headers=headers["analyst"]).json()
    assert len(events) == 6
    assert sum(event["hit"] for event in events) == 2

    incidents = client.get(
        "/incidents?severity=HIGH&limit=200", headers=headers["analyst"]
    ).json()
    incident = next(
        item for item in incidents if item["ip"] == ip and item["key"] == f"R1:{ip}"
    )
    assert incident["count"] == 2
    assert incident["severity"] == "HIGH"
    assert incident["status"] == "NEW"

    detail = client.get(f"/incidents/{incident['id']}", headers=headers["analyst"]).json()
    assert len(detail["related_events"]) == 2
    assert detail["timeline"][0]["kind"] == "system"

    assert client.patch(
        f"/incidents/{incident['id']}", json={"status": "CLOSED"}, headers=headers["analyst"]
    ).status_code == 400
    assert client.patch(
        f"/incidents/{incident['id']}", json={"owner": "analyst"}, headers=headers["viewer"]
    ).status_code == 403

    assigned = client.patch(
        f"/incidents/{incident['id']}", json={"owner": "analyst"}, headers=headers["analyst"]
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["status"] == "ASSIGNED"

    note = client.post(
        f"/incidents/{incident['id']}/notes",
        json={"text": "Blocked source IP at the firewall"},
        headers=headers["analyst"],
    )
    assert note.status_code == 200, note.text
    assert note.json()["ok"] is True

    resolved = client.post(
        f"/incidents/{incident['id']}/resolve",
        json={"resolution_summary": "Blocked and verified"},
        headers=headers["analyst"],
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "RESOLVED"

    assert client.post(
        f"/incidents/{incident['id']}/close", headers=headers["analyst"]
    ).status_code == 403
    closed = client.post(
        f"/incidents/{incident['id']}/close", headers=headers["manager"]
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "CLOSED"

    timeline = client.get(
        f"/incidents/{incident['id']}", headers=headers["manager"]
    ).json()["timeline"]
    assert any("Resolved:" in entry["text"] for entry in timeline)
    assert any("Closed by manager" in entry["text"] for entry in timeline)

    duplicate = ingest(client, ip)
    assert duplicate.status_code == 200
    assert duplicate.json()["new_incidents"] == 1
    reopened = client.get(
        "/incidents?limit=200", headers=headers["analyst"]
    ).json()
    assert any(
        item["ip"] == ip and item["status"] == "NEW" and item["count"] >= 2
        for item in reopened
    )


def test_simulation_and_validation(client, headers):
    ip = unique_ip("203.0.113")
    assert client.post(
        f"/events/simulate/bad_ip", headers=headers["viewer"]
    ).status_code == 403

    port_ip = unique_ip("203.0.113")
    scanned = ingest(
        client, port_ip, event_type="port_probe", count=8, user="-", source="pytest-ports"
    )
    assert scanned.status_code == 200, scanned.text
    incidents = client.get("/incidents?limit=500", headers=headers["analyst"]).json()
    port_incident = next(item for item in incidents if item["key"] == f"R4:{port_ip}")
    assert port_incident["severity"] == "MEDIUM"

    simulated = client.post("/events/simulate/bad_ip", headers=headers["admin"])
    assert simulated.status_code == 200, simulated.text
    assert simulated.json()["new_incidents"] == 1

    assert client.post("/events/simulate/nope", headers=headers["admin"]).status_code == 404
    assert client.post(
        "/events/ingest",
        json={"events": []},
        headers={"X-API-Key": "test-ingest-key"},
    ).status_code == 422
    assert client.post(
        "/events/ingest",
        json={
            "events": [
                {
                    "source_id": "x",
                    "ip": "1.1.1.1",
                    "event_type": "login_failed",
                    "detail": "x" * 5000,
                }
            ]
        },
        headers={"X-API-Key": "test-ingest-key"},
    ).status_code == 422
    assert client.get(f"/events?ip={ip}", headers=headers["viewer"]).status_code == 200
    assert client.get("/stats", headers=headers["viewer"]).status_code == 200
    assert client.get("/stats/dashboard", headers=headers["viewer"]).status_code == 200


def test_users_and_last_admin_protection(client, headers):
    suffix = uuid.uuid4().hex[:8]
    username = f"pytest-{suffix}"
    created = client.post(
        "/auth/users",
        json={
            "username": username,
            "email": "not-an-email",
            "password": "password123",
            "role": "VIEWER",
        },
        headers=headers["admin"],
    )
    assert created.status_code == 422

    created = client.post(
        "/auth/users",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "role": "VIEWER",
        },
        headers=headers["admin"],
    )
    assert created.status_code == 200, created.text
    assert created.json()["is_active"] is True

    assert client.post(
        "/auth/users",
        json={
            "username": username,
            "password": "password123",
            "role": "VIEWER",
        },
        headers=headers["admin"],
    ).status_code == 400
    assert client.post(
        "/auth/users",
        json={"username": f"x-{suffix}", "password": "password123", "role": "VIEWER"},
        headers=headers["analyst"],
    ).status_code == 403

    new_headers = login(client, username, "password123")
    assert client.get("/auth/me", headers=new_headers).json()["role"] == "VIEWER"
    assert client.patch(
        f"/auth/users/{username}",
        json={"password": "newpassword123"},
        headers=new_headers,
    ).status_code == 200
    assert client.get("/auth/me", headers=new_headers).status_code == 401

    assert client.patch(
        f"/auth/users/{username}", json={"role": "SECURITY_MANAGER"}, headers=headers["admin"]
    ).status_code == 200
    assert client.patch(
        "/auth/users/admin", json={"role": "SECURITY_ANALYST"}, headers=headers["admin"]
    ).status_code == 400
    assert client.patch(
        "/auth/users/admin", json={"is_active": False}, headers=headers["admin"]
    ).status_code == 400

    assert client.delete(
        f"/auth/users/{username}", headers=headers["admin"]
    ).status_code == 200
    assert client.get("/auth/users", headers=headers["admin"]).status_code == 200
    assert client.get("/auth/users", headers=headers["viewer"]).status_code == 403


def test_log_sources_and_rules(client, headers):
    suffix = uuid.uuid4().hex[:8]
    source_id = f"pytest-source-{suffix}"
    created = client.post(
        "/log-sources",
        json={"id": source_id, "name": "Pytest source", "source_type": "web"},
        headers=headers["admin"],
    )
    assert created.status_code == 200, created.text
    assert client.post(
        "/log-sources",
        json={"id": source_id, "name": "Duplicate", "source_type": "web"},
        headers=headers["admin"],
    ).status_code == 400
    assert client.post(
        "/log-sources",
        json={"id": f"x-{suffix}", "name": "Denied", "source_type": "web"},
        headers=headers["analyst"],
    ).status_code == 403
    assert client.get("/log-sources", headers=headers["viewer"]).status_code == 403

    response = ingest(
        client,
        unique_ip(),
        event_type="http_request",
        count=1,
        user="alice",
        source=source_id,
    )
    assert response.status_code == 200
    assert client.patch(
        f"/log-sources/{source_id}",
        json={"is_active": False},
        headers=headers["admin"],
    ).status_code == 200
    disabled = ingest(
        client,
        unique_ip(),
        event_type="http_request",
        count=1,
        user="alice",
        source=source_id,
    )
    assert disabled.status_code == 400
    assert client.patch(
        f"/log-sources/{source_id}",
        json={"is_active": True},
        headers=headers["admin"],
    ).status_code == 200
    assert client.delete(
        f"/log-sources/{source_id}", headers=headers["admin"]
    ).status_code == 400

    empty_id = f"pytest-empty-{suffix}"
    assert client.post(
        "/log-sources",
        json={"id": empty_id, "name": "Empty", "source_type": "generic"},
        headers=headers["admin"],
    ).status_code == 200
    assert client.delete(
        f"/log-sources/{empty_id}", headers=headers["admin"]
    ).status_code == 200

    rules = client.get("/rules", headers=headers["viewer"])
    assert rules.status_code == 200
    assert len(rules.json()) == 7
    assert client.patch(
        "/rules/R7", json={"enabled": False}, headers=headers["analyst"]
    ).status_code == 403

    try:
        assert client.patch(
            "/rules/R7", json={"enabled": False}, headers=headers["admin"]
        ).status_code == 200
        assert client.get("/rules/R7", headers=headers["admin"]).json()["enabled"] is False
    finally:
        assert client.patch(
            "/rules/R7", json={"enabled": True}, headers=headers["admin"]
        ).status_code == 200


def test_rule_overrides_survive_reinitialization(client, headers):
    assert client.patch(
        "/rules/R3",
        json={"threshold": 99, "enabled": False},
        headers=headers["admin"],
    ).status_code == 200

    db = SessionLocal()
    try:
        DetectionEngine(db).initialize_default_rules()
    finally:
        db.close()

    rule = client.get("/rules/R3", headers=headers["admin"]).json()
    assert rule["threshold"] == 99
    assert rule["enabled"] is False

    assert client.patch(
        "/rules/R3",
        json={"threshold": 30, "enabled": True},
        headers=headers["admin"],
    ).status_code == 200


def test_reports_notifications_and_audit(client, headers):
    daily = client.get("/stats/reports/daily", headers=headers["analyst"])
    assert daily.status_code == 200
    assert "total_events" in daily.json()
    assert client.get("/stats/reports/weekly", headers=headers["analyst"]).status_code == 200
    assert client.get("/stats/trends", headers=headers["viewer"]).status_code == 200
    assert client.get(
        "/stats/reports/performance", headers=headers["analyst"]
    ).status_code == 403
    assert client.get(
        "/stats/reports/performance", headers=headers["admin"]
    ).status_code == 200

    csv_response = client.get(
        "/stats/reports/export/csv", headers=headers["analyst"]
    )
    assert csv_response.status_code == 200
    assert "incident-report.csv" in csv_response.headers["content-disposition"]
    assert csv_response.text.startswith("ID,Title,Severity,Status")
    assert client.get(
        "/stats/reports/export/csv", headers=headers["viewer"]
    ).status_code == 403

    assert client.get("/notifications", headers=headers["admin"]).status_code == 200
    assert client.get("/notifications", headers=headers["viewer"]).status_code == 200
    analyst_notifications = client.get(
        "/notifications", headers=headers["analyst"]
    ).json()
    assert analyst_notifications
    assert all(
        item["status"] == "sent"
        for item in analyst_notifications
        if item["channel"] == "in_app"
    )
    assert client.get("/audit", headers=headers["analyst"]).status_code == 403
    audit = client.get("/audit?limit=500", headers=headers["admin"])
    assert audit.status_code == 200
    assert any(entry["action"] == "Logged in" for entry in audit.json())


def test_email_notification_uses_account_address(client, monkeypatch):
    from app.models import Notification
    from app.models.enums import NotificationChannel, NotificationStatus
    from app.services import notification as notification_module
    from app.services.notification import NotificationService

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=15):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, username, password):
            sent["login"] = username

        def send_message(self, message):
            sent["to"] = message["To"]
            sent["subject"] = message["Subject"]

    db = SessionLocal()
    try:
        notification = Notification(
            recipient="analyst",
            channel=NotificationChannel.EMAIL,
            subject="Test email",
            message="Test message",
            status=NotificationStatus.PENDING,
        )
        db.add(notification)
        db.commit()
        notification_id = notification.id

        monkeypatch.setattr(notification_module.settings, "SMTP_HOST", "smtp.example.com")
        monkeypatch.setattr(notification_module.settings, "SMTP_TLS", False)
        monkeypatch.setattr(notification_module.settings, "SMTP_USER", None)
        monkeypatch.setattr(notification_module.settings, "SMTP_PASS", None)
        monkeypatch.setattr(notification_module.smtplib, "SMTP", FakeSMTP)

        assert NotificationService(db).send_notification(notification_id) is True
        assert sent["to"] == "analyst@example.com"
        assert sent["host"] == "smtp.example.com"
        db.expire_all()
        stored = db.query(Notification).filter(Notification.id == notification_id).first()
        assert stored.status == NotificationStatus.SENT
        assert stored.sent_at is not None
    finally:
        db.close()
