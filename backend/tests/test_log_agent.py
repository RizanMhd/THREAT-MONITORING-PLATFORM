import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import log_agent


def test_ssh_line_parses_rfc5424_timestamp():
    event = log_agent.parse_line(
        "2026-10-26T12:20:05+00:00 host sshd[1]: Failed password for admin "
        "from 198.51.100.78 port 2206 ssh2",
        "ssh",
        None,
    )

    assert event["event_type"] == "login_failed"
    assert event["ip"] == "198.51.100.78"
    assert event["ts"] == datetime(
        2026, 10, 26, 12, 20, 5, tzinfo=timezone.utc
    ).timestamp()


def test_traditional_syslog_timestamp_is_not_ingest_time():
    now = datetime.now().astimezone()
    parsed = datetime(now.year, 1, 2, 3, 4, 5, tzinfo=now.tzinfo)
    if parsed > now + timedelta(days=1):
        parsed = parsed.replace(year=now.year - 1)

    event = log_agent.parse_line(
        "Jan  2 03:04:05 host sshd[1]: Failed password for admin "
        "from 198.51.100.79 port 2206 ssh2",
        "ssh",
        None,
    )

    assert event["ts"] == parsed.timestamp()


def test_nginx_line_uses_its_own_timestamp():
    event = log_agent.parse_line(
        '198.51.100.2 - - [26/Oct/2026:12:20:00 +0000] "GET /admin HTTP/1.1" 403 12',
        "nginx",
        None,
    )

    assert event["event_type"] == "http_request"
    assert event["ts"] == datetime(
        2026, 10, 26, 12, 20, tzinfo=timezone.utc
    ).timestamp()
