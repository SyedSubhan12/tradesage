# user_session_models.py

from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base
import uuid

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    session_id = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    refresh_token_hash = Column(
        String(255),
        nullable=False
    )
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )
    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    last_used_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    client_ip = Column(String(100), nullable=True)  # IP address of the client
    user_agent = Column(String, nullable=True)  # User agent string of the client

    # Relationship back to User
    user = relationship("User", back_populates="user_sessions")

    __table_args__ = (
        # Quickly find active sessions for a given user
        Index("idx_user_session_user_active", "user_id", "is_active"),
        # Clean up expired sessions efficiently
        Index("idx_user_session_expires", "expires_at"),
    )
