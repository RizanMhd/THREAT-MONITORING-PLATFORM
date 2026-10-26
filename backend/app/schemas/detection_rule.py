from pydantic import BaseModel, ConfigDict, Field
from typing import Optional
from app.models.detection_rule import SeverityLevel


class DetectionRuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    condition: str
    severity: SeverityLevel
    threshold: Optional[int] = None
    time_window_seconds: Optional[int] = None


class DetectionRuleCreate(DetectionRuleBase):
    id: str


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    enabled: Optional[bool] = None
    threshold: Optional[int] = None
    time_window_seconds: Optional[int] = None


class DetectionRuleResponse(DetectionRuleBase):
    id: str
    enabled: bool
    created_at: str
    updated_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)