import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Index, Integer, LargeBinary
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base

class SessionAuditLog(Base):
    """Audit trail for all session related activities"""
    __tablename__ = "session_audit_log"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    user_id = Column(String(50), nullable=False, index=True, doc="User ID")

    action = Column(String(50), nullable=False, doc="Action performed")
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # state details
    old_state = Column(String(20), nullable=True, doc="Previous state")
    new_state = Column(String(20), nullable=True, doc="New state")
    data_size = Column(Integer, nullable=True, doc="Size of the data")

    #context
    ip_address = Column(String(50), nullable=True, doc="IP Address")
    user_agent = Column(String(255), nullable=True, doc="User Agent")
    event_metadata = Column(JSONB, default={}, nullable=True, doc="Additional metadata")    

    __table_args__ = (
        Index("idx_session_audit_timestamp", "session_id", "timestamp"),
        Index("idx_audit_user_timestamp", "user_id", "timestamp"),
    )