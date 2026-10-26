from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.session import get_db
from app.models.enums import IncidentStatus, UserRole
from app.schemas.stats import DashboardStats
from app.services.incident_management import IncidentManagementService
from app.services.reporting import ReportingService


router = APIRouter(prefix="/stats", tags=["statistics & reporting"])

READ_ROLES = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
    UserRole.VIEWER,
)
REPORT_ROLES = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
)


@router.get("", response_model=DashboardStats)
@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*READ_ROLES)),
):
    return ReportingService(db).get_dashboard_stats()


@router.get("/trends", response_model=List[dict])
def get_incident_trends(
    days: int = 7,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*READ_ROLES)),
):
    return ReportingService(db).get_incident_trends(days)


@router.get("/workload", response_model=List[dict])
def get_analyst_workload(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*REPORT_ROLES)),
):
    return ReportingService(db).get_analyst_workload()


@router.get("/reports/daily", response_model=dict)
def get_daily_summary(
    date: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*REPORT_ROLES)),
):
    parsed = None
    if date:
        try:
            parsed = datetime.fromisoformat(date)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid date format") from exc
    return ReportingService(db).generate_daily_summary(parsed)


@router.get("/reports/weekly", response_model=dict)
def get_weekly_summary(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*REPORT_ROLES)),
):
    return ReportingService(db).generate_weekly_summary()


@router.get("/reports/incident/{incident_id}", response_model=dict)
def get_incident_report(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*READ_ROLES)),
):
    report = ReportingService(db).generate_incident_report(incident_id)
    if not report:
        raise HTTPException(status_code=404, detail="Incident not found")
    return report


@router.get("/reports/trends", response_model=dict)
def get_trend_report(
    days: int = 30,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*REPORT_ROLES)),
):
    return ReportingService(db).generate_trend_report(days)


@router.get("/reports/performance", response_model=dict)
def get_performance_report(
    db: Session = Depends(get_db),
    current_user=Depends(
        require_role(UserRole.SYSTEM_ADMIN, UserRole.SECURITY_MANAGER)
    ),
):
    return ReportingService(db).generate_performance_report()


@router.get("/reports/export/csv")
def export_incidents_csv(
    status: Optional[IncidentStatus] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*REPORT_ROLES)),
):
    incidents = IncidentManagementService(db).get_incidents(
        status=status, limit=1000
    )
    csv_data = ReportingService(db).export_incidents_csv(incidents)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=incident-report.csv"},
    )
