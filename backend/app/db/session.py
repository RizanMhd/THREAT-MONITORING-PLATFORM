from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import get_settings


Base = declarative_base()


def _configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


def build_engine():
    settings = get_settings()
    if settings.DATABASE_URL.startswith("sqlite"):
        if ":memory:" not in settings.DATABASE_URL:
            db_path = settings.DATABASE_URL.replace("sqlite:///", "", 1).replace("sqlite://", "", 1)
            Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            settings.DATABASE_URL,
            connect_args={"check_same_thread": False, "timeout": 30},
            pool_pre_ping=True,
        )
        _configure_sqlite(engine)
        return engine

    return create_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


engine = build_engine()
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    bind=engine,
)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
