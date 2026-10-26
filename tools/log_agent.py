"""Tail a log file and ship normalized security events to SecureWatch.

Install this on monitored hosts and point it at an auth or web log:

    python log_agent.py --path /var/log/auth.log --format ssh
    python log_agent.py --path /var/log/nginx/access.log --format nginx
    python log_agent.py --path C:\\logs\\events.jsonl --format json

The agent stores its read offset in a state file and retries failed batches.
Delivery is at-least-once: an event can be sent twice if the process dies after
the API accepted a batch but before the state file was updated.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except Exception:
    pass


LOGGER = logging.getLogger("securewatch.log-agent")
SSH_RE = re.compile(
    r"(Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
)
WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>[^"]*?)(?:\s+HTTP/[^"]*)?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
)
ISO_TS_RE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
SYSLOG_TS_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s"
)
NGINX_TS_RE = re.compile(
    r"^(?P<day>\d{1,2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<sign>[+-])(?P<offset_hour>\d{2})(?P<offset_minute>\d{2})$"
)
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _timestamp(value: Any) -> float:
    if value is None or value == "":
        return time.time()
    if isinstance(value, (int, float)):
        return float(value) / (1000.0 if value > 10_000_000_000 else 1.0)
    if isinstance(value, str):
        stripped = value.strip()
        try:
            numeric = float(stripped)
            return numeric / (1000.0 if numeric > 10_000_000_000 else 1.0)
        except ValueError:
            pass
        try:
            parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            pass
    return time.time()


def _line_timestamp(line: str) -> float:
    iso_match = ISO_TS_RE.match(line)
    if iso_match:
        return _timestamp(iso_match.group("stamp"))

    syslog_match = SYSLOG_TS_RE.match(line)
    if not syslog_match:
        return time.time()

    month = MONTHS.get(syslog_match.group("month"))
    if not month:
        return time.time()

    now = datetime.now().astimezone()
    try:
        parsed = datetime(
            now.year,
            month,
            int(syslog_match.group("day")),
            int(syslog_match.group("hour")),
            int(syslog_match.group("minute")),
            int(syslog_match.group("second")),
            tzinfo=now.tzinfo,
        )
    except ValueError:
        return time.time()

    if parsed > now + timedelta(days=1):
        try:
            parsed = parsed.replace(year=now.year - 1)
        except ValueError:
            return time.time()
    return parsed.timestamp()


def _web_timestamp(value: str) -> float:
    match = NGINX_TS_RE.match(value.strip())
    if not match:
        return time.time()

    month = MONTHS.get(match.group("month"))
    if not month:
        return time.time()

    try:
        sign = 1 if match.group("sign") == "+" else -1
        offset = timezone(
            sign
            * timedelta(
                hours=int(match.group("offset_hour")),
                minutes=int(match.group("offset_minute")),
            )
        )
        parsed = datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=offset,
        )
    except ValueError:
        return time.time()
    return parsed.timestamp()


def _clean(value: Any, limit: int, default: str = "-") -> str:
    text = default if value is None or value == "" else str(value)
    return text[:limit]


def _event_type(value: Any) -> str:
    event_type = _clean(value, 50, "unknown").strip().lower().replace(" ", "_")
    return event_type or "unknown"


def build_event(
    *,
    source_id: str,
    ip: Any,
    user: Any,
    event_type: Any,
    country: Any = "-",
    detail: Any = "",
    role: Any = None,
    ts: Any = None,
) -> Dict[str, Any]:
    return {
        "source_id": source_id,
        "ip": _clean(ip, 45, "0.0.0.0"),
        "user": _clean(user, 100),
        "event_type": _event_type(event_type),
        "country": _clean(country, 8).upper(),
        "detail": _clean(detail, 4000, ""),
        "role": _clean(role, 50) if role not in (None, "") else None,
        "ts": _timestamp(ts),
    }


def parse_line(line: str, log_format: str, source_id: Optional[str]) -> Optional[Dict[str, Any]]:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    stripped = line.strip()
    parsed_json = None
    if stripped.startswith("{"):
        try:
            parsed_json = json.loads(stripped)
        except json.JSONDecodeError:
            parsed_json = None

    if log_format in ("json", "auto") and isinstance(parsed_json, dict):
        resolved_source = source_id or _clean(
            parsed_json.get("source_id") or parsed_json.get("source"), 50, "log-agent"
        )
        detail = parsed_json.get("detail")
        if detail is None:
            detail = json.dumps(parsed_json, separators=(",", ":"), ensure_ascii=True)
        return build_event(
            source_id=resolved_source,
            ip=parsed_json.get("ip")
            or parsed_json.get("source_ip")
            or parsed_json.get("clientip")
            or parsed_json.get("remote_addr"),
            user=parsed_json.get("user")
            or parsed_json.get("username")
            or parsed_json.get("account"),
            event_type=parsed_json.get("event_type")
            or parsed_json.get("type")
            or parsed_json.get("action"),
            country=parsed_json.get("country", "-"),
            detail=detail,
            role=parsed_json.get("role"),
            ts=parsed_json.get("ts")
            or parsed_json.get("timestamp")
            or parsed_json.get("time"),
        )

    ssh_match = SSH_RE.search(line)
    if ssh_match and log_format in ("ssh", "auto"):
        return build_event(
            source_id=source_id or "ssh-auth",
            ip=ssh_match.group(3),
            user=ssh_match.group(2),
            event_type="login_failed" if ssh_match.group(1) == "Failed" else "login_success",
            detail=line,
            ts=_line_timestamp(line),
        )

    web_match = WEB_RE.match(line)
    if web_match and log_format in ("nginx", "web", "auto"):
        return build_event(
            source_id=source_id or "web-server",
            ip=web_match.group("ip"),
            user="-",
            event_type="http_request",
            detail=f"{web_match.group('method')} {web_match.group('path')} {web_match.group('status')}",
            ts=_web_timestamp(web_match.group("time")),
        )

    return None


def send_batch(url: str, key: str, events: List[Dict[str, Any]], retries: int = 6) -> None:
    endpoint = url.rstrip("/") + "/events/ingest"
    body = json.dumps({"events": events}).encode()
    delay = 1.0
    last_error: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json", "X-API-Key": key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode())
                LOGGER.info("shipped %s events: %s", len(events), payload)
                return
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            last_error = RuntimeError(f"HTTP {exc.code}: {detail}")
            if exc.code in (401, 403):
                raise SystemExit(f"Ingestion rejected ({exc.code}): {detail}") from exc
            if exc.code == 400:
                LOGGER.error("batch rejected by API: %s", detail)
                return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc

        if attempt < retries:
            LOGGER.warning("send failed (attempt %s/%s): %s", attempt, retries, last_error)
            time.sleep(delay)
            delay = min(delay * 2, 30)

    raise RuntimeError(f"failed to ship {len(events)} events: {last_error}")


def load_offset(state_file: Path, log_path: Path, from_start: bool) -> int:
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if Path(state.get("path", "")).resolve() == log_path.resolve():
                return max(int(state.get("offset", 0)), 0)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            LOGGER.warning("ignoring unreadable state file %s", state_file)
    return 0 if from_start else log_path.stat().st_size


def save_offset(state_file: Path, log_path: Path, offset: int) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_file.with_suffix(state_file.suffix + ".tmp")
    temporary.write_text(
        json.dumps({"path": str(log_path.resolve()), "offset": offset}),
        encoding="utf-8",
    )
    temporary.replace(state_file)


def run(args: argparse.Namespace) -> int:
    log_path = Path(args.path).expanduser().resolve()
    state_file = Path(args.state_file).expanduser().resolve()
    if not log_path.exists():
        raise SystemExit(f"log file does not exist: {log_path}")

    offset = load_offset(state_file, log_path, args.from_start)
    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)

    LOGGER.info("tailing %s from byte %s as %s", log_path, offset, args.source_id or "auto")

    while running:
        try:
            file_size = log_path.stat().st_size
        except FileNotFoundError:
            LOGGER.warning("log file missing, waiting: %s", log_path)
            time.sleep(args.poll_interval)
            continue

        if offset > file_size:
            LOGGER.info("log file rotated or truncated, restarting at byte 0")
            offset = 0

        with log_path.open("rb") as handle:
            handle.seek(offset)
            read_offset = offset
            saved_offset = offset
            buffer: List[Dict[str, Any]] = []
            last_flush = time.monotonic()

            def flush() -> None:
                nonlocal saved_offset, last_flush
                if buffer:
                    send_batch(args.url, args.key, buffer)
                    buffer.clear()
                if read_offset != saved_offset:
                    save_offset(state_file, log_path, read_offset)
                    saved_offset = read_offset
                last_flush = time.monotonic()

            while running:
                line = handle.readline()
                if line:
                    read_offset = handle.tell()
                    event = parse_line(
                        line.decode("utf-8", errors="replace"),
                        args.format,
                        args.source_id,
                    )
                    if event:
                        buffer.append(event)
                    if len(buffer) >= args.batch_size:
                        flush()
                    continue

                if buffer and time.monotonic() - last_flush >= args.flush_seconds:
                    flush()
                elif read_offset != saved_offset and time.monotonic() - last_flush >= 60:
                    flush()

                if args.once:
                    flush()
                    return 0

                time.sleep(args.poll_interval)
                try:
                    if log_path.stat().st_size < read_offset:
                        LOGGER.info("log file rotated while tailing, reopening")
                        flush()
                        offset = 0
                        break
                except FileNotFoundError:
                    break

            flush()
            if args.once:
                return 0
            if running:
                time.sleep(args.poll_interval)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureWatch log shipping agent")
    parser.add_argument("--path", required=True, help="log file to tail")
    parser.add_argument("--format", default="auto", choices=["auto", "ssh", "nginx", "web", "json"])
    parser.add_argument("--source-id", default=None, help="SecureWatch log source ID")
    parser.add_argument("--url", default=os.getenv("SW_URL", "http://localhost:8000"))
    parser.add_argument(
        "--key",
        default=os.getenv("SW_INGEST_KEY") or os.getenv("INGEST_KEY", "change-this-ingest-key"),
    )
    parser.add_argument(
        "--state-file",
        default=str(Path.home() / ".securewatch-log-agent.json"),
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--flush-seconds", type=float, default=3.0)
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument("--from-start", action="store_true", help="replay the file from the beginning")
    parser.add_argument("--once", action="store_true", help="process current data and exit")
    args = parser.parse_args()

    if not 1 <= args.batch_size <= 500:
        parser.error("--batch-size must be between 1 and 500")
    remote_host = urllib.parse.urlsplit(args.url).hostname
    if not args.key or (
        args.key == "change-this-ingest-key"
        and remote_host not in {"localhost", "127.0.0.1", "::1", None}
    ):
        LOGGER.warning("using the default ingest key; configure INGEST_KEY or --key")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        LOGGER.error("agent stopped: %s", exc)
        raise SystemExit(1)
