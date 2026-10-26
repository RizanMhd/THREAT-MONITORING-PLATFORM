from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.session import get_db
from app.models import DetectionRule
from app.models.enums import UserRole
from app.schemas.detection_rule import DetectionRuleResponse, DetectionRuleUpdate
from app.services.audit import record_audit


router = APIRouter(prefix="/rules", tags=["detection rules"])

ANY_ROLE = (
    UserRole.SYSTEM_ADMIN,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_MANAGER,
    UserRole.VIEWER,
)


@router.get("", response_model=List[DetectionRuleResponse])
def list_rules(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*ANY_ROLE)),
):
    return db.query(DetectionRule).order_by(DetectionRule.id).all()


@router.get("/{rule_id}", response_model=DetectionRuleResponse)
def get_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(*ANY_ROLE)),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
def update_rule(
    rule_id: str,
    update_data: DetectionRuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        if key == "enabled":
            setattr(rule, key, 1 if value else 0)
        else:
            setattr(rule, key, value)

    record_audit(
        db,
        current_user.username,
        f"Updated detection rule {rule_id}",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/initialize", response_model=dict)
def initialize_default_rules(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSTEM_ADMIN)),
):
    from app.services.detection import DetectionEngine

    DetectionEngine(db).initialize_default_rules()
    record_audit(db, current_user.username, "Initialized default detection rules")
    db.commit()
    return {"ok": True, "message": "Default rules initialized"}
