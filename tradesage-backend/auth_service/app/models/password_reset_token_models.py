from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base
import uuid

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

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
    token = Column(
        String(255),
        unique=True,
        nullable=False
    )  # This should store the hashed reset token
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )
    used = Column(
        Boolean,
        default=False,
        nullable=False
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relationship back to User model
    user = relationship("User", back_populates="password_reset_tokens")


    __table_args__ = (
        # Index to quickly find active/unused tokens by user
        Index("idx_password_reset_token_user_used", "user_id", "used"),
        # Index to efficiently clean up expired tokens
        Index("idx_password_reset_token_expires", "expires_at"),
    )
