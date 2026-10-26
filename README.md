# SecureWatch

SecureWatch is a self-hosted security incident management and threat monitoring platform for small
security teams. It ingests real security events over an authenticated API, applies detection rules,
correlates alerts into incidents, and provides a role-based web console for investigation, reporting,
notifications, and audit.

The frontend in `frontend/` is served by the FastAPI application and uses the real API. There is no
mock data layer.

## Features

- Real log ingestion with an API key, batch validation, and automatic log-source registration.
- Detection rules R1-R7 with configurable thresholds and enable/disable controls.
- Incident correlation and deduplication, risk scoring, severity escalation, and linked events.
- Incident lifecycle: new, assigned, investigating, escalated, resolved, closed.
- Investigation notes, timeline, related events, owner assignment, and resolution summaries.
- Role-based access control: administrator, analyst, manager, viewer.
- Live dashboard with 4-second polling, event search, incident workspace, rules, sources, users, audit.
- In-app notifications and optional SMTP email delivery.
- Reports, CSV export, health endpoints, request IDs, security headers, and rate limiting.
- Linux log agent, Windows Event Log agent, and a test event simulator.
- SQLite for single-node deployments or PostgreSQL for production.

## Architecture

```
backend/app/api/          FastAPI routers
backend/app/core/         settings, seed data, middleware, rate limiting
backend/app/db/           SQLAlchemy engine and sessions
backend/app/models/       users, events, incidents, notes, notifications, audit
backend/app/schemas/      request and response validation
backend/app/services/     auth, detection, correlation, incidents, reporting, notifications
backend/tests/            API and detection tests
frontend/                 HTML, CSS, and JavaScript console served by FastAPI
tools/                    log agents, simulator, backup, notification runner
deploy/                   Nginx and systemd examples
data/                     local SQLite database (created on first start)
```

The server seeds default log sources, detection rules, and a development administrator on first start.
No frontend build step or Node.js installation is required.

## Local quick start

Windows PowerShell:

```powershell
python -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install -r backend\requirements.txt
Copy-Item .env.example .env
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cp .env.example .env
.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/>. In development, API documentation is at `/docs`.

Development accounts created on an empty database:

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | System administrator |
| `analyst` | `analyst123` | Security analyst |
| `manager` | `manager123` | Security manager |
| `viewer` | `viewer123` | Read-only viewer |

Change these credentials before exposing the service. In production, set `BOOTSTRAP_ADMIN_PASSWORD`
and leave `BOOTSTRAP_DEMO_USERS=false`.

The local database is `data/securewatch.db`. To reset a development database, stop the server and
delete `data/securewatch.db`, `data/securewatch.db-wal`, and `data/securewatch.db-shm`.

## Tests

```powershell
Set-Location backend
& "..\.venv\Scripts\python.exe" -m pytest -q
```

```bash
cd backend
../.venv/bin/python -m pytest -q
```

## Sending real events

`POST /events/ingest` accepts a batch of normalized events and requires `X-API-Key`. The source is
created automatically if it does not exist.

```bash
curl -X POST http://127.0.0.1:8000/events/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-this-ingest-key" \
  -d '{"events":[{"source_id":"web-server","ip":"203.0.113.10","user":"admin","event_type":"login_failed","country":"RU","detail":"Failed password"}]}'
```

Example response:

```json
{"accepted": 1, "new_incidents": 0, "alerts": 0}
```

Normalized event fields:

| Field | Required | Meaning |
|---|---|---|
| `source_id` | yes | Log source identifier |
| `ip` | yes | Source IP address |
| `event_type` | yes | `login_failed`, `login_success`, `http_request`, `port_probe`, IAM/cloud events |
| `user` | no | Account name |
| `country` | no | ISO country code or `-` |
| `detail` | no | Raw detail or request path |
| `role` | no | User role for privilege checks |
| `ts` | no | Unix seconds, Unix milliseconds, or omitted for server time |

`POST /events/ingest/raw` accepts raw dictionaries and normalizes common CloudTrail, CloudWatch,
IDS, and generic shapes.

The simulator is admin-only and disabled when `ENABLE_TEST_ENDPOINTS=false`:

```bash
python tools/simulate.py --scenario brute_force
python tools/simulate.py --scenario all --url http://127.0.0.1:8000
```

Scenarios: `brute_force`, `port_scan`, `request_flood`, `new_country`, `admin_access`, `bad_ip`,
`config_change`, `normal`, `all`.

## Log agents

Linux auth log:

```bash
python3 tools/log_agent.py --path /var/log/auth.log --format ssh --source-id ssh-auth
```

Nginx access log:

```bash
python3 tools/log_agent.py --path /var/log/nginx/access.log --format nginx --source-id web-server
```

JSON lines:

```bash
python3 tools/log_agent.py --path /var/log/securewatch/events.jsonl --format json
```

The agent keeps a byte offset, retries failed batches with backoff, and uses at-least-once delivery.
Use `--once` for a one-shot import and `--from-start` to replay a file. Configure the URL and key with
`SW_URL` and `SW_INGEST_KEY`, or pass `--url` and `--key`.

Windows Security log agent (run PowerShell as Administrator):

```powershell
.\tools\windows_event_agent.ps1 -Url http://securewatch.example.com -ApiKey "YOUR_INGEST_KEY"
```

It reads successful and failed logon events (4624/4625), tracks the last record ID, and can be tested
with `-Once`. Schedule it with Task Scheduler and run it under an account that can read the Security log.

## Detection rules

| Rule | Behavior | Default severity |
|---|---|---|
| R1 | 5 failed logins from one IP in 120 seconds | High |
| R2 | Successful login from a country different from the user baseline | Medium |
| R3 | 30 HTTP requests from one IP in 60 seconds | High |
| R4 | 8 distinct ports probed from one IP in 60 seconds | Medium |
| R5 | Non-admin user requests an `/admin` path | Critical |
| R6 | Event from a blocklisted IP | Critical |
| R7 | Security-relevant configuration change by a non-admin user | High |

Thresholds and windows are stored in the database. Administrators can toggle rules; editing a rule
through the API updates its stored configuration.

## Roles

| Area | Admin | Analyst | Manager | Viewer |
|---|---|---|---|---|
| Dashboard, events, incidents, rules | read | read | read | read |
| Incident updates and notes | write | write | write | no |
| Resolve incidents | yes | yes | yes | no |
| Close incidents | yes | no | yes | no |
| Log sources | manage | read | read | no |
| Users and audit | manage | no | no | no |
| Reports and CSV | yes | yes | yes | read-only stats |
| Test simulator | yes | no | no | no |

## Configuration

Settings are read from environment variables and the repository `.env` file. See `.env.example`
and `.env.production.example`.

Important settings:

| Setting | Purpose |
|---|---|
| `ENVIRONMENT` | `development` or `production`; production enables secret validation |
| `SECRET_KEY` | HMAC token signing key; at least 32 unique characters in production |
| `INGEST_KEY` | API key for event ingestion; at least 16 characters in production |
| `DATABASE_URL` | SQLAlchemy URL; defaults to SQLite at `data/securewatch.db` |
| `DB_PATH` | Alternative SQLite path |
| `ENABLE_DOCS` | Serve `/docs` and OpenAPI |
| `ENABLE_TEST_ENDPOINTS` | Enable admin simulation endpoints |
| `ALLOWED_HOSTS` | Comma-separated TrustedHost values |
| `CORS_ORIGINS` | Comma-separated allowed browser origins |
| `TRUST_PROXY_HEADERS` | Trust `X-Forwarded-For`; enable only behind a trusted proxy |
| `BOOTSTRAP_ADMIN_PASSWORD` | First administrator password; required for an empty production database |
| `BOOTSTRAP_DEMO_USERS` | Create development demo accounts |
| `MAX_INGEST_BATCH` | Maximum events per ingestion request |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | Login attempts per IP and username |
| `BACKUP_RETENTION_DAYS` | Backup rotation period |
| SMTP settings | Optional email notification delivery |

Production validation rejects default secrets, wildcard CORS, and short bootstrap passwords.

## Production deployment

A public deployment requires a server, a DNS name, TLS certificates, and credentials. Those are
environment-specific and are not included in this repository.

### Docker Compose with PostgreSQL and Nginx

1. Point a DNS record at the server and open only ports 22, 80, and 443.
2. Copy `.env.production.example` to `.env.production` and fill every value.
3. Generate secrets with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
4. Start the application and database:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

The app binds to `127.0.0.1:8000`; it is not directly exposed. Put Nginx in front of it. First obtain
the certificate through the HTTP-only bootstrap configuration:

```bash
sudo mkdir -p /var/www/certbot
sudo cp deploy/nginx-bootstrap.conf /etc/nginx/sites-available/securewatch
sudo ln -s /etc/nginx/sites-available/securewatch /etc/nginx/sites-enabled/securewatch
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
sudo certbot certonly --webroot -w /var/www/certbot -d soc.example.com
sudo cp deploy/nginx.conf /etc/nginx/sites-available/securewatch
sudo nginx -t && sudo systemctl reload nginx
```

Update `server_name` and certificate paths in `deploy/nginx.conf`. Keep `FORCE_HTTPS=false` when Nginx
terminates TLS; HSTS is set by Nginx. Set `ALLOWED_HOSTS` and `CORS_ORIGINS` to the real hostname.
The sample Nginx configuration overwrites `X-Forwarded-For` with the real peer address; if you use a
different proxy or load balancer, make sure it cannot pass a client-supplied forwarded header through.

### systemd without Docker

```bash
sudo useradd --system --home /opt/securewatch --shell /usr/sbin/nologin securewatch
sudo mkdir -p /opt/securewatch
sudo rsync -a --exclude .venv --exclude .env --exclude data --exclude backups ./ /opt/securewatch/
sudo chown -R securewatch:securewatch /opt/securewatch
sudo -u securewatch python3 -m venv /opt/securewatch/.venv
sudo -u securewatch /opt/securewatch/.venv/bin/python -m pip install -r /opt/securewatch/backend/requirements.txt
sudo install -m 600 .env.production /opt/securewatch/.env.production
sudo cp deploy/securewatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now securewatch
```

Use the same Nginx configuration. Change the PostgreSQL host in `DATABASE_URL` from `db` to
`localhost` (or the managed database host). The unit writes only to `data/` and `backups/` because of
systemd hardening; keep those directories owned by the service user.

### Post-deployment checks

- `curl https://soc.example.com/health/ready`
- Sign in with the bootstrap administrator and immediately change the password.
- Create named users and disable or remove unused accounts.
- Confirm `ENABLE_DOCS=false` and `ENABLE_TEST_ENDPOINTS=false`.
- Send one test event through the ingestion API and verify it appears under Events.
- Confirm backups and notification timers are active.

## Backups and restore

SQLite backups use the online backup API and work while the server is running:

```bash
python tools/backup.py --output-dir backups --retention-days 30
```

PostgreSQL backups use `pg_dump`; the Docker image includes it, while bare-metal hosts need the
PostgreSQL client tools installed. Backups are gzip-compressed and timestamped.

For a daily systemd timer, install `deploy/securewatch-backup.service` and
`deploy/securewatch-backup.timer`. Copy backups off the server and test restores regularly.

SQLite restore:

```bash
sudo systemctl stop securewatch
gunzip -c backups/securewatch-YYYYmmdd-HHMMSS.db.gz | sudo tee data/securewatch.db > /dev/null
sudo chown securewatch:securewatch data/securewatch.db
sudo systemctl start securewatch
```

PostgreSQL restore:

```bash
gunzip -c backups/securewatch-YYYYmmdd-HHMMSS.sql.gz | psql "$DATABASE_URL"
```

For Docker, run the backup inside the application container and copy it off-host regularly:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml exec \
  securewatch python tools/backup.py
docker compose --env-file .env.production -f docker-compose.prod.yml cp \
  securewatch:/srv/backups/. ./offsite-backups/
```

## Notifications

High and critical incidents create in-app notifications for analysts, managers, and administrators.
When SMTP is configured, matching email notifications are queued for the email address on each account.
Deliver queued email with:

```bash
python tools/process_notifications.py
```

Install `deploy/securewatch-notifications.service` and `.timer` for a two-minute schedule. In-app
notifications are visible in the dashboard without an email worker.

## Security notes

- Passwords use PBKDF2-HMAC-SHA256 with 260,000 iterations and random salts.
- Tokens are HMAC-signed, expiring, versioned, and stored in browser session storage. Changing a
  password revokes existing tokens for that account.
- Ingestion requires a constant-time-compared API key.
- API authorization is enforced server-side; frontend role checks are only for presentation.
- Login attempts are rate-limited per IP and username. The limiter is in-process, so run one worker
  or add a shared Redis limiter before scaling horizontally.
- Security headers include CSP, frame denial, no-sniff, referrer policy, and HSTS behind HTTPS.
- The container runs as a non-root user with `no-new-privileges`.
- Audit logs cover authentication, user, rule, source, incident, and automated correlation actions.
- No MFA is built in. Put internet-facing deployments behind identity-aware SSO/MFA or add it before
  exposing the platform to untrusted networks.

## Operations

- Health: `/health/live` for process liveness, `/health/ready` and `/health` for database readiness.
- Logs: the application logs to stdout/journald with request IDs and process times.
- API errors: FastAPI returns structured `detail` messages; the UI displays them.
- If the UI says the API cannot be reached, confirm the server is running and the browser is using the
  same origin.
- If login returns 429, wait for the login rate-limit window to expire.

## API summary

| Method and path | Access | Purpose |
|---|---|---|
| `POST /auth/login` | public | Obtain a token |
| `GET /auth/me` | authenticated | Current user |
| `GET /auth/assignees` | admin, analyst, manager | Assignable users |
| `POST/GET/PATCH/DELETE /auth/users` | admin | User administration |
| `POST /events/ingest` | API key | Batch ingest normalized events |
| `POST /events/ingest/raw` | API key | Normalize and ingest raw events |
| `GET /events`, `GET /events/{id}` | any authenticated | Event search |
| `POST /events/simulate/{scenario}` | admin | Test detection pipeline |
| `GET/PATCH /incidents`, `GET /incidents/{id}` | any authenticated / write roles | Incident workspace |
| `POST /incidents/{id}/notes` | admin, analyst, manager | Add investigation note |
| `POST /incidents/{id}/escalate` | admin, analyst, manager | Escalate |
| `POST /incidents/{id}/resolve` | admin, analyst, manager | Resolve with summary |
| `POST /incidents/{id}/close` | admin, manager | Close a resolved incident |
| `GET/PATCH /rules` | any authenticated / admin | Detection rules |
| `GET/POST/PATCH/DELETE /log-sources` | read roles / admin | Log sources |
| `GET /stats`, `/stats/dashboard`, `/stats/trends` | any authenticated | Dashboard metrics |
| `GET /stats/reports/*` | report roles | Reports |
| `GET /stats/reports/export/csv` | admin, analyst, manager | Incident CSV |
| `GET /notifications` | any authenticated | Own notifications |
| `POST /notifications/process-pending` | admin | Deliver queued notifications |
| `GET /audit` | admin | Audit trail |

## Limitations and next steps

- Schema changes currently use `create_all`; add Alembic migrations before evolving a production database.
- SQLite is single-node. Use PostgreSQL for multiple workers or hosts.
- The login/test rate limiter is in-process; use Redis before horizontal scaling.
- Detection baselines for unusual-country logins are simple and should be tuned per environment.
- There is no built-in MFA, SOAR automation, case evidence storage, or external threat-intelligence API.
- Email delivery requires the notification worker/timer; in-app notifications work without SMTP.
