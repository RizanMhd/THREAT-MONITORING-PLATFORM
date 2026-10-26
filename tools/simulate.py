"""Send realistic test events to a running SecureWatch API.

Examples:
    python tools/simulate.py --scenario brute_force
    python tools/simulate.py --scenario all --url http://localhost:8000
    python tools/simulate.py --scenario port_scan --key "$INGEST_KEY"
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except Exception:
    pass


SCENARIOS = (
    "brute_force",
    "port_scan",
    "request_flood",
    "new_country",
    "admin_access",
    "bad_ip",
    "config_change",
    "normal",
    "all",
)


def random_ip() -> str:
    return f"203.0.113.{random.randint(1, 250)}"


def event(**kwargs: Any) -> Dict[str, Any]:
    payload = {
        "source_id": "simulator",
        "ip": random_ip(),
        "user": "-",
        "country": "-",
        "detail": "",
        "role": None,
        "ts": time.time(),
    }
    payload.update(kwargs)
    return payload


def scenario(name: str) -> List[Dict[str, Any]]:
    now = time.time()
    if name == "brute_force":
        ip = random_ip()
        return [
            event(
                ip=ip,
                user="admin",
                event_type="login_failed",
                country="RU",
                detail="Failed password",
                ts=now - (5 - index) * 0.2,
            )
            for index in range(6)
        ]
    if name == "port_scan":
        ip = random_ip()
        return [
            event(
                ip=ip,
                event_type="port_probe",
                country="NL",
                detail=str(20 + index * 11),
                ts=now - (10 - index) * 0.1,
            )
            for index in range(10)
        ]
    if name == "request_flood":
        ip = random_ip()
        return [
            event(
                ip=ip,
                event_type="http_request",
                country="CN",
                detail="/index",
                ts=now - (32 - index) * 0.05,
            )
            for index in range(32)
        ]
    if name == "new_country":
        return [
            event(
                user=random.choice(["alice", "bob"]),
                event_type="login_success",
                country="BR",
                detail="OAuth login",
            )
        ]
    if name == "admin_access":
        return [
            event(
                user="bob",
                role="staff",
                event_type="http_request",
                country="LK",
                detail="/admin/users",
            )
        ]
    if name == "bad_ip":
        return [
            event(
                ip="185.220.101.7",
                event_type="http_request",
                country="RU",
                detail="/wp-login.php",
            )
        ]
    if name == "config_change":
        return [
            event(
                user="bob",
                role="staff",
                event_type="security_group_modified",
                country="LK",
                detail="AuthorizeSecurityGroupIngress 0.0.0.0/0 port 22",
            )
        ]
    if name == "normal":
        events = []
        for _ in range(10):
            user = random.choice(["alice", "bob", "carol"])
            events.append(
                event(
                    user=user,
                    role="staff",
                    event_type=random.choice(["http_request", "login_success"]),
                    country="SG" if user == "carol" else "LK",
                    detail=random.choice(["/home", "/profile", "/reports"]),
                )
            )
        return events
    raise ValueError(f"Unknown scenario: {name}")


def send(url: str, key: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    body = json.dumps({"events": events}).encode()
    request = urllib.request.Request(
        url.rstrip("/") + "/events/ingest",
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach {url}: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureWatch test event simulator")
    parser.add_argument("--scenario", default="all", choices=SCENARIOS)
    parser.add_argument("--url", default=os.getenv("SW_URL", "http://localhost:8000"))
    parser.add_argument(
        "--key",
        default=os.getenv("SW_INGEST_KEY") or os.getenv("INGEST_KEY", "change-this-ingest-key"),
    )
    args = parser.parse_args()

    names = list(SCENARIOS[:-1]) if args.scenario == "all" else [args.scenario]
    for name in names:
        events = scenario(name)
        result = send(args.url, args.key, events)
        print(f"{name}: {result}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
