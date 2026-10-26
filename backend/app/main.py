import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import (
    audit,
    auth,
    detection_rules,
    events,
    incidents,
    log_sources,
    notifications,
    stats,
)
from app.core.config import get_settings
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.seed import seed_all
from app.db.session import get_db, init_db


settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("securewatch")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if not os.getenv("TESTING"):
        db = next(get_db())
        try:
            seed_all(db)
        finally:
            db.close()
    app.state.started_at = datetime.utcnow()
    logger.info(
        "SecureWatch %s started environment=%s database=%s",
        settings.APP_VERSION,
        settings.ENVIRONMENT,
        settings.DATABASE_URL.split("://", 1)[0],
    )
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_DOCS else None,
)

if settings.allowed_hosts_list != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Process-Time-Ms"],
)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
if settings.FORCE_HTTPS:
    app.add_middleware(HTTPSRedirectMiddleware)

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(detection_rules.router)
app.include_router(stats.router)
app.include_router(log_sources.router)
app.include_router(notifications.router)
app.include_router(audit.router)


@app.get("/health/live")
def live_check():
    return {"status": "ok"}


@app.get("/health/ready")
@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Health check database failure")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "database": "unavailable"},
        )

    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "database": "ok",
        "test_endpoints": settings.ENABLE_TEST_ENDPOINTS,
    }


FRONTEND_PATH = Path(settings.FRONTEND_DIR).resolve()
if FRONTEND_PATH.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_PATH, html=True), name="ui")
else:
    logger.warning("Frontend directory not found at %s", FRONTEND_PATH)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
