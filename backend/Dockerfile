FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FRONTEND_DIR=/srv/frontend \
    DB_PATH=/data/securewatch.db \
    FORWARDED_ALLOW_IPS=127.0.0.1

WORKDIR /srv

COPY backend/requirements.txt /srv/backend/requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r /srv/backend/requirements.txt

COPY backend/app /srv/backend/app
COPY frontend /srv/frontend
COPY tools /srv/tools

RUN useradd --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data /srv/backups \
    && chown -R app:app /data /srv/backups

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=4)"

STOPSIGNAL SIGTERM

CMD ["uvicorn", "app.main:app", "--app-dir", "/srv/backend", "--host", "0.0.0.0", "--port", "8000"]
