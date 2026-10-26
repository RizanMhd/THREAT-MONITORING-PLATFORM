from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any

from app.schemas.common import UTCDateTime


class LogSourceBase(BaseModel):
    name: str
    source_type: str
    config: Optional[Dict[str, Any]] = None


class LogSourceCreate(LogSourceBase):
    id: str


class LogSourceUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class LogSourceResponse(LogSourceBase):
    id: str
    is_active: bool
    created_at: UTCDateTime
    updated_at: Optional[UTCDateTime] = None

    model_config = ConfigDict(from_attributes=True)