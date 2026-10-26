"""Deliver pending email notifications. Run from cron or a systemd timer."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.db.session import SessionLocal  # noqa: E402
from app.services.notification import NotificationService  # noqa: E402


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    db = SessionLocal()
    try:
        NotificationService(db).process_pending_notifications()
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
