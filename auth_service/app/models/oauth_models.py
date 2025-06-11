from sqlalchemy import Column, String, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.sql import func
from .base import Base
import uuid

class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String(255), unique=True, nullable=False)
    client_secret = Column(String(255), nullable=True) # Hashed/encrypted in production
    redirect_uris = Column(ARRAY(Text), nullable=False)
    grant_types = Column(ARRAY(Text), nullable=False)
    scopes = Column(ARRAY(Text), nullable=False)
    is_confidential = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())