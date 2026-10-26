import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATA_DIR = REPO_ROOT / "data"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "securewatch.db"
ENV_FILE = REPO_ROOT / ".env"

DEFAULT_SECRET_KEY = "change-this-long-random-string"
DEFAULT_INGEST_KEY = "change-this-ingest-key"


def _sqlite_url(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("sqlite"):
        return normalized
    return f"sqlite:///{normalized}"


class Settings(BaseSettings):
    APP_NAME: str = "SecureWatch"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    ENABLE_DOCS: bool = True
    ENABLE_TEST_ENDPOINTS: bool = True
    FORCE_HTTPS: bool = False
    TRUST_PROXY_HEADERS: bool = False

    ALLOWED_HOSTS: str = "*"
    CORS_ORIGINS: str = "http://localhost:8000,http://127.0.0.1:8000"

    DATABASE_URL: str = ""
    DB_PATH: Optional[str] = None
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    SECRET_KEY: str = DEFAULT_SECRET_KEY
    INGEST_KEY: str = DEFAULT_INGEST_KEY
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_HOURS: int = 8
    PASSWORD_MIN_LENGTH: int = 8
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 10

    BOOTSTRAP_ADMIN_USERNAME: str = "admin"
    BOOTSTRAP_ADMIN_EMAIL: Optional[str] = "admin@example.com"
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = None
    BOOTSTRAP_DEMO_USERS: bool = True

    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASS: Optional[str] = None
    SMTP_TLS: bool = True
    MAIL_FROM: str = "securewatch@localhost"
    MAIL_TO: str = "soc@localhost"

    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    SNS_TOPIC_ARN: Optional[str] = None

    FRONTEND_DIR: str = str(REPO_ROOT / "frontend")
    CORRELATION_WINDOW_SECONDS: int = 300
    DEDUPLICATION_WINDOW_SECONDS: int = 300

    MAX_INGEST_BATCH: int = 500
    MAX_REQUEST_BYTES: int = 5_000_000
    MAX_EVENT_DETAIL_LENGTH: int = 4000
    BACKUP_RETENTION_DAYS: int = 14

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def resolve_database_url(self):
        if self.DATABASE_URL:
            if self.DATABASE_URL.startswith("postgres://"):
                self.DATABASE_URL = self.DATABASE_URL.replace("postgres://", "postgresql://", 1)
            return self

        db_path = self.DB_PATH or os.getenv("DB_PATH")
        if not db_path:
            db_path = str(DEFAULT_DB_PATH)

        if db_path.startswith("sqlite"):
            self.DATABASE_URL = db_path
        else:
            candidate = Path(db_path)
            if not candidate.is_absolute():
                candidate = REPO_ROOT / candidate
            self.DATABASE_URL = _sqlite_url(candidate.as_posix())
        return self

    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.ENVIRONMENT.lower() != "production":
            return self

        if self.SECRET_KEY == DEFAULT_SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY must be a unique value of at least 32 characters in production")
        if self.INGEST_KEY == DEFAULT_INGEST_KEY or len(self.INGEST_KEY) < 16:
            raise ValueError("INGEST_KEY must be a unique value of at least 16 characters in production")
        if self.CORS_ORIGINS.strip() == "*":
            raise ValueError("CORS_ORIGINS must list explicit origins in production")
        if self.BOOTSTRAP_ADMIN_PASSWORD and len(self.BOOTSTRAP_ADMIN_PASSWORD) < 12:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters in production")
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def allowed_hosts_list(self) -> list[str]:
        if self.ALLOWED_HOSTS.strip() == "*":
            return ["*"]
        return [host.strip() for host in self.ALLOWED_HOSTS.split(",") if host.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
