from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_events: int
    events_last_24h: int
    total_incidents: int
    incidents_last_24h: int
    open_incidents: int
    unassigned_incidents: int
    critical_high_incidents: int
    open_by_severity: Dict[str, int]
    top_ips: List[Dict[str, Any]]
    avg_resolution_seconds: Optional[float] = None
    mttd_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None


class IncidentTrend(BaseModel):
    date: str
    count: int
    severity: str


class TopSourceIP(BaseModel):
    ip: str
    count: int


class AnalystWorkload(BaseModel):
    analyst: str
    assigned_count: int
    resolved_count: int


class ReportRequest(BaseModel):
    report_type: str
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    format: str = "csv"


class DailySummaryReport(BaseModel):
    date: str
    total_events: int
    total_incidents: int
    incidents_by_severity: Dict[str, int]
    top_threats: List[Dict[str, Any]]
