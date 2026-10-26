import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.common import UTCDateTime


class EventBase(BaseModel):
    ip: str = Field(min_length=1, max_length=45)
    user: Optional[str] = Field(default="-", max_length=100)
    event_type: str = Field(min_length=1, max_length=50)
    country: Optional[str] = Field(default="-", max_length=8)
    detail: Optional[str] = Field(default="", max_length=4000)
    role: Optional[str] = Field(default=None, max_length=50)
    source_id: str = Field(min_length=1, max_length=50)
    raw_data: Optional[Dict[str, Any]] = None

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        return value.strip().lower().replace(" ", "_")

    @field_validator("country")
    @classmethod
    def normalize_country(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return "-"
        return value.strip().upper() or "-"


class EventCreate(EventBase):
    ts: float = Field(default_factory=time.time)

    @field_validator("ts", mode="before")
    @classmethod
    def normalize_timestamp(cls, value: Optional[float]) -> float:
        if value is None:
            return time.time()
        value = float(value)
        if value > 10_000_000_000:
            return value / 1000.0
        return value


class EventBatchCreate(BaseModel):
    events: List[EventCreate] = Field(min_length=1, max_length=500)


class EventResponse(EventBase):
    id: int
    ts: float
    hit: int
    created_at: UTCDateTime

    model_config = ConfigDict(from_attributes=True)


class EventFilter(BaseModel):
    limit: int = Field(default=200, ge=1, le=1000)
    ip: Optional[str] = None
    user: Optional[str] = None
    event_type: Optional[str] = None
    source_id: Optional[str] = None
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    hit_only: bool = False
