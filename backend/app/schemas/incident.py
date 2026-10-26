from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IncidentStatus, SeverityLevel
from app.schemas.common import UTCDateTime


class IncidentBase(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=4000)
    severity: SeverityLevel
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    asset_criticality: Optional[str] = Field(default=None, max_length=20)
    detection_confidence: Optional[float] = Field(default=None, ge=0, le=1)
    potential_impact: Optional[str] = Field(default=None, max_length=20)


class IncidentCreate(IncidentBase):
    key: str = Field(min_length=1, max_length=200)
    ip: Optional[str] = None
    status: IncidentStatus = IncidentStatus.NEW


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    owner: Optional[str] = Field(default=None, max_length=100)
    severity: Optional[SeverityLevel] = None
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    asset_criticality: Optional[str] = Field(default=None, max_length=20)
    detection_confidence: Optional[float] = Field(default=None, ge=0, le=1)
    potential_impact: Optional[str] = Field(default=None, max_length=20)


class IncidentResponse(IncidentBase):
    id: int
    key: str
    status: IncidentStatus
    owner: Optional[str] = None
    count: int
    ip: Optional[str] = None
    created_at: UTCDateTime
    updated_at: Optional[UTCDateTime] = None
    resolved_at: Optional[UTCDateTime] = None
    closed_at: Optional[UTCDateTime] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailResponse(IncidentResponse):
    timeline: List[dict] = []
    related_events: List[dict] = []


class NoteCreate(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class ResolveRequest(BaseModel):
    resolution_summary: str = Field(min_length=1, max_length=4000)


class IncidentFilter(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[SeverityLevel] = None
    owner: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
