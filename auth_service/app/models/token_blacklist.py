# token_blacklist_models.py

from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base
import uuid

class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    token_hash = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relationship back to User
    user = relationship("User", back_populates="blacklisted_tokens")

    __table_args__ = (
        # Allow efficient cleanup of expired blacklisted tokens
        Index("idx_token_blacklist_expires", "expires_at"),
        # Quickly query by user to see all their revoked tokens
        Index("idx_token_blacklist_user", "user_id"),
    )
