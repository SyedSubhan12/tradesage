# app/models/tenant.py

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, DateTime, Boolean, Float, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class TenantSchema(Base):
    """Model for tracking tenant database schemas."""
    __tablename__ = "tenant_schemas"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, unique=True)
    schema_name = Column(String(100), unique=True, nullable=False)
    template_used = Column(String(50), default="trading")
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    provisioning_time_seconds = Column(Float)
    
    # Relationships
    backups = relationship("TenantBackup", back_populates="schema")
    metrics = relationship("TenantMetric", back_populates="schema")
    
    __table_args__ = (
        Index("idx_tenant_schemas_tenant_id", "tenant_id"),
    )


class TenantBackup(Base):
    """Model for tenant backup records."""
    __tablename__ = "tenant_backups"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False)
    schema_id = Column(UUID(as_uuid=True), ForeignKey("tenant_schemas.id"))
    backup_id = Column(String(255), unique=True, nullable=False)
    schema_name = Column(String(100), nullable=False)
    backup_path = Column(String, nullable=False)
    size_bytes = Column(Float)
    backup_type = Column(String(50))  # 'scheduled', 'manual', 'pre_migration'
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at = Column(DateTime(timezone=True))
    is_deleted = Column(Boolean, default=False)
    
    # Relationships
    schema = relationship("TenantSchema", back_populates="backups")
    
    __table_args__ = (
        Index("idx_tenant_backups_tenant_id", "tenant_id"),
        Index("idx_tenant_backups_created", "created_at"),
    )


class TenantMetric(Base):
    """Model for tenant resource metrics."""
    __tablename__ = "tenant_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False)
    schema_id = Column(UUID(as_uuid=True), ForeignKey("tenant_schemas.id"))
    schema_name = Column(String(100), nullable=False)
    metric_type = Column(String(50), nullable=False)  # 'storage', 'performance', 'usage'
    metric_value = Column(JSON, nullable=False)
    collected_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationships
    schema = relationship("TenantSchema", back_populates="metrics")
    
    __table_args__ = (
        Index("idx_tenant_metrics_tenant_collected", "tenant_id", "collected_at"),
        Index("idx_tenant_metrics_type", "metric_type"),
    ) 