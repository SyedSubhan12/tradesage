from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Integer,
    Enum as SQLEnum,
    ForeignKey,
    Text,
)
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from enum import Enum
import uuid
from sqlalchemy.orm import relationship
from common.database import Base

# Removed imports to avoid circular import
# from auth_service.app.models.password_reset_token_models import PasswordResetToken
# from auth_service.app.models.user_session import UserSession
# from auth_service.app.models.token_blacklist import TokenBlacklist


class UserRole(str, Enum):
    ADMIN = "admin"
    TRADER = "trader"
    VIEWER = "viewer"
    API_USER = "api_user"


class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"
    CANCELLED = "cancelled"


class BaseTenant(Base):
    """Base tenant model"""
    __tablename__ = "tenants"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    name = Column(String(225), nullable=False)
    domain = Column(String(225), nullable=True, unique=True, index=True)
    schema_name = Column(String(100), nullable=True, unique=True, index=True)
    status = Column(SQLEnum(TenantStatus), default=TenantStatus.PENDING)
    settings = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Role(Base):
    __tablename__ = "roles"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    name = Column(String(50), unique=True)
    permissions = Column(JSONB)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))

    tenant = relationship("Tenant", back_populates="roles")


class Tenant(BaseTenant):
    """Tenant model with relationships"""
    __tablename__ = "tenants"

    users = relationship(
        "User",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )
    roles = relationship(
        "Role",
        back_populates="tenant",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    oauth_clients = relationship(
        "auth_service.app.models.oauth_models.OAuthClient",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )
    api_keys = relationship(
        "ApiKey",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )
    api_users = relationship(
        "ApiUser",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )

    __mapper_args__ = {"polymorphic_identity": "tenant"}


class BaseUser(Base):
    __tablename__ = 'users'

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    username = Column(String(225), nullable=False, unique=True, index=True)
    email = Column(String(225), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(225), nullable=True)
    last_name = Column(String(225), nullable=True)
    role = Column(SQLEnum(UserRole), default=UserRole.TRADER)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    user_metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class User(BaseUser):
    """User model with tenant and token/session relationships"""
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id"),
        nullable=False
    )
    tenant = relationship("Tenant", back_populates="users")

    # Password reset tokens relationship
    password_reset_tokens = relationship(
        "auth_service.app.models.password_reset_token_models.PasswordResetToken",
        back_populates="user"
    )

    # User sessions relationship
    user_sessions = relationship(
        "auth_service.app.models.user_session.UserSession",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # Blacklisted tokens relationship
    blacklisted_tokens = relationship(
        "auth_service.app.models.token_blacklist.TokenBlacklist",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    __mapper_args__ = {"polymorphic_identity": "user"}


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    name = Column(String(100))
    key = Column(String(100), unique=True)
    scopes = Column(JSONB)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id")
    )

    tenant = relationship("Tenant", back_populates="api_keys")


class ApiUser(Base):
    __tablename__ = "api_users"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    name = Column(String(100))
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id")
    )

    tenant = relationship("Tenant", back_populates="api_users")