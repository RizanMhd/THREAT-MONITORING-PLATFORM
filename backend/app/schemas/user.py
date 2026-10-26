from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.enums import UserRole
from app.schemas.common import UTCDateTime


class UserBase(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.@-]+$")
    email: Optional[EmailStr] = None
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_not_blank(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value.strip() != value:
            raise ValueError("Password must not start or end with whitespace")
        return value


class UserResponse(UserBase):
    is_active: bool
    created_at: UTCDateTime

    model_config = ConfigDict(from_attributes=True)


class AssigneeResponse(BaseModel):
    username: str
    role: UserRole


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    token: str
    role: UserRole
    username: str


class TokenPayload(BaseModel):
    sub: str
    role: UserRole
    exp: int
