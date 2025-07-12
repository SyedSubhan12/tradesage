import uuid
from enum import Enum
from sqlalchemy import Column, String, DateTime, Boolean, Index, Integer, LargeBinary, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from common.database import Base
from sqlalchemy.orm import relationship

class SessionState(Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"
    TERMINATED = "TERMINATED"

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    session_token = Column(String(64), unique=True, nullable=False, index=True)
    refresh_token_hash = Column(String(255), nullable=True) # Made nullable to support sessions without refresh tokens
    previous_refresh_token_hash = Column(String(255), nullable=True)
    previous_refresh_token_expires_at = Column(DateTime(timezone=True), nullable=True)

    # State management
    state = Column(SQLEnum(SessionState, native_enum=False, create_constraint=True))
    encrypted_data = Column(LargeBinary, nullable=True) # Nullable for sessions that only track auth state
    version = Column(Integer, default=1, nullable=False)
    
    # Timestamps
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_accessed = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # Relationship back to user
    user = relationship("User", back_populates="user_sessions")

    # Metadata for auditing and security
    client_ip = Column(JSONB, nullable=True)
    user_agent = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_user_session_user_state", "user_id", "state"),
        Index("idx_user_session_expires", "expires_at"),
        Index("idx_user_session_last_accessed", "last_accessed"),
    )

    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id}, is_active={self.is_active})>"
