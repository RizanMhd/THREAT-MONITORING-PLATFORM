"""Create and rotate SecureWatch database backups.

SQLite uses the online backup API, so the database can stay in use.
PostgreSQL uses pg_dump and requires pg_dump on PATH.

    python tools/backup.py
    python tools/backup.py --output-dir D:\\backups --retention-days 30
"""
from __future__ import annotations

import argparse
import gzip
import logging
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.core.config import get_settings  # noqa: E402


LOGGER = logging.getLogger("securewatch.backup")


def sqlite_path(database_url: str) -> Path:
    if database_url.startswith("sqlite:////"):
        return Path("/" + database_url[len("sqlite:////") :])
    if database_url.startswith("sqlite:///"):
        return Path(database_url[len("sqlite:///") :])
    raise ValueError("Only file-based SQLite URLs are supported")


def backup_sqlite(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"database does not exist: {source}")

    temporary = target.with_suffix(".db.tmp")
    source_connection = sqlite3.connect(str(source), timeout=30)
    target_connection = sqlite3.connect(str(temporary))
    try:
        source_connection.backup(target_connection)
        integrity = target_connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError(f"backup integrity check failed: {integrity}")
    finally:
        target_connection.close()
        source_connection.close()

    with temporary.open("rb") as raw, gzip.open(target, "wb", compresslevel=6) as compressed:
        shutil.copyfileobj(raw, compressed)
    temporary.unlink(missing_ok=True)
    LOGGER.info("SQLite backup written to %s", target)


def backup_postgres(database_url: str, target: Path) -> None:
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        raise RuntimeError("pg_dump is not installed or not on PATH")

    temporary = target.with_suffix(".sql.tmp")
    with temporary.open("wb") as raw:
        process = subprocess.run(
            [pg_dump, "--no-owner", "--no-privileges", "--dbname", database_url],
            stdout=raw,
            stderr=subprocess.PIPE,
            check=False,
            timeout=3600,
        )
    if process.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(process.stderr.decode(errors="replace").strip())

    with temporary.open("rb") as raw, gzip.open(target, "wb", compresslevel=6) as compressed:
        shutil.copyfileobj(raw, compressed)
    temporary.unlink(missing_ok=True)
    LOGGER.info("PostgreSQL backup written to %s", target)


def rotate(output_dir: Path, retention_days: int) -> None:
    if retention_days <= 0:
        return
    cutoff = time.time() - timedelta(days=retention_days).total_seconds()
    for path in output_dir.glob("securewatch-*.gz"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                LOGGER.info("Removed expired backup %s", path)
        except OSError:
            LOGGER.warning("Could not inspect or remove %s", path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Back up the SecureWatch database")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "backups"))
    parser.add_argument("--retention-days", type=int, default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = get_settings()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    retention_days = (
        args.retention_days
        if args.retention_days is not None
        else settings.BACKUP_RETENTION_DAYS
    )

    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    database_url = settings.DATABASE_URL
    if database_url.startswith("sqlite"):
        target = output_dir / f"securewatch-{stamp}.db.gz"
        backup_sqlite(sqlite_path(database_url), target)
    elif database_url.startswith(("postgresql://", "postgres://")):
        target = output_dir / f"securewatch-{stamp}.sql.gz"
        backup_postgres(database_url.replace("postgres://", "postgresql://", 1), target)
    else:
        raise RuntimeError(f"Unsupported DATABASE_URL: {database_url.split(':', 1)[0]}")

    rotate(output_dir, retention_days)
    print(target)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        LOGGER.error("backup failed: %s", exc)
        raise SystemExit(1)
