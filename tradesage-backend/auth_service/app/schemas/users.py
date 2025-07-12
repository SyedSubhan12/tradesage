from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from uuid import UUID as UUIDType
from typing import Optional

from common.models import UserRole

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    role: UserRole = UserRole.TRADER
    tenant_id: Optional[UUIDType] = None

    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        # Map common role names to valid roles
        role_mapping = {
            "user": "trader",
            "administrator": "admin",
            "view": "viewer",
            "api": "api_user"
        }
        
        # If it's a string and in our mapping, convert it
        if isinstance(v, str) and v.lower() in role_mapping:
            v = role_mapping[v.lower()]
            
        try:
            return UserRole(v)
        except ValueError:
            valid_roles = [role.value for role in UserRole]
            raise ValueError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or not any(c.isupper() for c in v) or not any(c.islower() for c in v) or not any(c.isdigit() for c in v):
            raise ValueError("Password must be at least 8 chars, contain upper, lower, and digit")
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError("Username can only contain letters, numbers, hyphens, and underscores")
        return v

class UserResponse(BaseModel):
    id: str
    tenant_id: str
    tenant_status: str
    username: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: UserRole
    is_active: bool
    is_verified: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    created_at: datetime