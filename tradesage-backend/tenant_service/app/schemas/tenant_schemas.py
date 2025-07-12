# app/schemas/tenant_schemas.py

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator
import uuid


# Base schemas
class TenantSchemaBase(BaseModel):
    """Base schema for tenant schema operations.
    
    This is the base Pydantic model that other tenant schema models inherit from.
    It defines the common fields and validation logic shared across tenant schema operations.
    
    Fields:
        template_used (str): The template to use when creating the tenant's schema.
            Defaults to "trading" which provides the full trading platform schema.
            This field is used by the SchemaProvisioner service to determine which
            template schema to clone when setting up a new tenant.
            
    Usage:
        This base model is inherited by TenantSchemaCreate for validating schema creation
        requests and TenantSchemaResponse for standardizing API responses.
    """
    template_used: str = Field(
        default="trading",
        description="Template to use for schema creation"
    )


class TenantSchemaCreate(TenantSchemaBase):
    """Schema for creating a new tenant schema.
    
    This schema validates the input parameters when creating a new tenant schema.
    It inherits from TenantSchemaBase which provides the template_used field.
    
    Fields:
        tenant_id (UUID): Required. The unique identifier for the tenant. This ID is used
            to generate a secure schema name and track the tenant's resources.
        template_used (str): Optional, defaults to "trading". The template to use for 
            schema creation. Must be one of: "trading", "analytics", or "minimal".
            - trading: Full trading platform schema with all tables
            - analytics: Schema optimized for analytics workloads
            - minimal: Basic schema with essential tables only
    
    Validation:
        - Validates that template_used is one of the allowed templates
        - tenant_id must be a valid UUID
    """
    tenant_id: uuid.UUID = Field(..., description="Unique tenant identifier")
    
    @validator('template_used')
    def validate_template(cls, v):
        allowed_templates = ["trading", "analytics", "minimal"]
        if v not in allowed_templates:
            raise ValueError(f"Template must be one of: {allowed_templates}")
        return v


class TenantSchemaResponse(TenantSchemaBase):
    """Response schema for tenant schema operations."""
    id: uuid.UUID
    tenant_id: uuid.UUID
    schema_name: str
    created_at: datetime
    is_active: bool
    provisioning_time_seconds: Optional[float]
    
    class Config:
        from_attributes = True


# Backup schemas
class BackupCreate(BaseModel):
    """Schema for creating a backup."""
    tenant_id: uuid.UUID
    backup_type: str = Field(default="manual", description="Type of backup")
    
    @validator('backup_type')
    def validate_backup_type(cls, v):
        allowed_types = ["manual", "scheduled", "pre_migration"]
        if v not in allowed_types:
            raise ValueError(f"Backup type must be one of: {allowed_types}")
        return v


class BackupResponse(BaseModel):
    """Response schema for backup operations."""
    id: uuid.UUID
    tenant_id: uuid.UUID
    backup_id: str
    schema_name: str
    backup_path: str
    size_bytes: Optional[float]
    backup_type: str
    created_at: datetime
    expires_at: Optional[datetime]
    is_deleted: bool = False
    
    class Config:
        from_attributes = True


# Monitoring schemas
class MetricData(BaseModel):
    """Schema for metric data."""
    storage_mb: float = Field(..., description="Storage used in MB")
    table_count: int = Field(..., description="Number of tables")
    row_count: int = Field(..., description="Total row count")
    index_count: int = Field(..., description="Number of indexes")
    connection_count: int = Field(..., description="Active connections")


class TenantMetricResponse(BaseModel):
    """Response schema for tenant metrics."""
    id: uuid.UUID
    tenant_id: uuid.UUID
    schema_name: str
    metric_type: str
    metric_value: Dict[str, Any]
    collected_at: datetime
    
    class Config:
        from_attributes = True


# Tenant operation schemas
class TenantProvisionRequest(BaseModel):
    """Request to provision a new tenant."""
    tenant_id: uuid.UUID
    organization_name: str
    template: str = Field(default="trading", description="Schema template to use")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict)


class TenantProvisionResponse(BaseModel):
    """Response for tenant provisioning."""
    tenant_id: uuid.UUID
    schema_name: str
    template: str
    status: str
    provisioning_time: float
    created_at: datetime
    connection_string: Optional[str] = None


class TenantStatusResponse(BaseModel):
    """Response for tenant status check."""
    tenant_id: uuid.UUID
    schema_name: str
    is_active: bool
    created_at: datetime
    last_backup: Optional[datetime]
    metrics: Optional[Dict[str, Any]]
    health_status: str  # 'healthy', 'degraded', 'unhealthy'


class TenantListResponse(BaseModel):
    """Response for listing tenants."""
    tenants: List[TenantSchemaResponse]
    total: int
    page: int
    page_size: int 