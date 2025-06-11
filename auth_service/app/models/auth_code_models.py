from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base
import uuid

class AuthCode(Base):
    __tablename__ = "auth_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    client_id = Column(UUID(as_uuid=True), ForeignKey('oauth_clients.id'), nullable=False)
    code = Column(String(255), unique=True, nullable=False)
    redirect_uri = Column(String(255), nullable=False)
    code_challenge = Column(String(255), nullable=False)
    code_challenge_method = Column(String(50), nullable=False) # e.g., S256 or plain
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", backref="auth_codes")
    client = relationship("OAuthClient", backref="auth_codes")