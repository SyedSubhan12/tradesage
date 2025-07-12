# app/routers/v1/tenants.py

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
import asyncpg
import structlog

from tenant_service.app.schemas.tenant_schemas import (
    TenantProvisionRequest,
    TenantProvisionResponse,
    TenantStatusResponse,
    TenantListResponse,
    TenantSchemaResponse
)
from tenant_service.app.services.schema_provisioner import SchemaProvisioner
from tenant_service.app.services.monitoring_service import TenantMonitoringService
from tenant_service.app.models.tenant import TenantSchema, TenantBackup
from common.database import db_manager
from common.redis_client import redis_manager
from common.auth import require_admin, get_current_user

logger = structlog.get_logger(__name__)

router = APIRouter()


# Dependency to get database session
async def get_db():
    async with db_manager.get_session() as session:
        yield session


# Dependency to get provisioner
async def get_provisioner():
    # Create connection pool for provisioner
    pool = await asyncpg.create_pool(db_manager.engine.url.render_as_string(hide_password=False))
    try:
        yield SchemaProvisioner(pool)
    finally:
        await pool.close()


# Dependency to get monitoring service
def get_monitoring_service():
    return TenantMonitoringService(db_manager.get_session, redis_manager.client)


@router.post("/provision", response_model=TenantProvisionResponse, status_code=status.HTTP_201_CREATED)
async def provision_tenant(
    request: TenantProvisionRequest,
    db: AsyncSession = Depends(get_db),
    provisioner: SchemaProvisioner = Depends(get_provisioner),
    current_user = Depends(require_admin)
):
    """
    Provision a new tenant schema.
    
    This endpoint creates a new isolated database schema for a tenant
    with all necessary tables, indexes, and security policies.
    """
    try:
        # Check if tenant already has a schema
        existing = await db.execute(
            select(TenantSchema).where(TenantSchema.tenant_id == request.tenant_id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Tenant {request.tenant_id} already has a schema"
            )
        
        # Provision the schema
        result = await provisioner.provision_tenant_schema(
            str(request.tenant_id),
            request.template
        )
        
        # Create response
        return TenantProvisionResponse(
            tenant_id=request.tenant_id,
            schema_name=result["schema_name"],
            template=result["template"],
            status="active",
            provisioning_time=result["provisioning_time"],
            created_at=result["created_at"]
        )
        
    except Exception as e:
        logger.error(
            "Failed to provision tenant",
            tenant_id=str(request.tenant_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to provision tenant: {str(e)}"
        )


@router.get("/{tenant_id}/status", response_model=TenantStatusResponse)
async def get_tenant_status(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    monitoring_service: TenantMonitoringService = Depends(get_monitoring_service),
    current_user = Depends(get_current_user)
):
    """
    Get tenant status and health information.
    
    Returns current status, health metrics, and recent backup information.
    """
    # Get tenant schema
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    # Get latest backup
    backup_result = await db.execute(
        select(TenantBackup)
        .where(TenantBackup.tenant_id == tenant_id)
        .order_by(TenantBackup.created_at.desc())
        .limit(1)
    )
    latest_backup = backup_result.scalar_one_or_none()
    
    # Get health status
    health_status = await monitoring_service.get_tenant_health_status(tenant_id)
    
    # Get latest metrics
    metrics = await monitoring_service.get_tenant_metrics(tenant_id)
    
    return TenantStatusResponse(
        tenant_id=tenant_id,
        schema_name=tenant_schema.schema_name,
        is_active=tenant_schema.is_active,
        created_at=tenant_schema.created_at,
        last_backup=latest_backup.created_at if latest_backup else None,
        metrics=metrics,
        health_status=health_status
    )


@router.get("/", response_model=TenantListResponse)
async def list_tenants(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    List all tenant schemas with pagination.
    
    Returns a paginated list of tenant schemas with basic information.
    """
    # Build query
    query = select(TenantSchema)
    
    if is_active is not None:
        query = query.where(TenantSchema.is_active == is_active)
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query)
    tenants = result.scalars().all()
    
    return TenantListResponse(
        tenants=[TenantSchemaResponse.from_orm(t) for t in tenants],
        total=total,
        page=page,
        page_size=page_size
    )


@router.post("/{tenant_id}/deactivate", status_code=status.HTTP_200_OK)
async def deactivate_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Deactivate a tenant schema.
    
    This prevents access to the tenant's data but doesn't delete it.
    """
    # Get tenant schema
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    if not tenant_schema.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant {tenant_id} is already inactive"
        )
    
    # Deactivate
    tenant_schema.is_active = False
    await db.commit()
    
    # Clear cache
    await redis_manager.client.delete(f"tenant:metrics:{tenant_id}")
    
    logger.info("Tenant deactivated", tenant_id=tenant_id)
    
    return {"message": f"Tenant {tenant_id} deactivated successfully"}


@router.post("/{tenant_id}/activate", status_code=status.HTTP_200_OK)
async def activate_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Activate a deactivated tenant schema.
    
    Re-enables access to the tenant's data.
    """
    # Get tenant schema
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    if tenant_schema.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant {tenant_id} is already active"
        )
    
    # Activate
    tenant_schema.is_active = True
    await db.commit()
    
    logger.info("Tenant activated", tenant_id=tenant_id)
    
    return {"message": f"Tenant {tenant_id} activated successfully"}


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: str,
    force: bool = Query(False, description="Force delete even with data"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Delete a tenant and all associated data.
    
    This is a destructive operation that permanently removes all tenant data.
    Use the 'force' parameter to bypass safety checks.
    """
    # Get tenant schema
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    try:
        # Create connection for schema operations
        pool = await asyncpg.create_pool(db_manager.engine.url.render_as_string(hide_password=False))
        
        try:
            async with pool.acquire() as conn:
                # Check if schema has data (unless force is True)
                if not force:
                    table_count = await conn.fetchval(f"""
                        SELECT count(*) 
                        FROM pg_tables 
                        WHERE schemaname = '{tenant_schema.schema_name}'
                    """)
                    
                    if table_count > 0:
                        # Check if any tables have data
                        has_data = False
                        tables = await conn.fetch(f"""
                            SELECT tablename 
                            FROM pg_tables 
                            WHERE schemaname = '{tenant_schema.schema_name}'
                        """)
                        
                        for table in tables:
                            row_count = await conn.fetchval(
                                f'SELECT count(*) FROM "{tenant_schema.schema_name}"."{table["tablename"]}"'
                            )
                            if row_count > 0:
                                has_data = True
                                break
                        
                        if has_data:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Schema contains data. Use force=true to delete anyway."
                            )
                
                # Drop the schema
                await conn.execute(f'DROP SCHEMA IF EXISTS "{tenant_schema.schema_name}" CASCADE')
                
        finally:
            await pool.close()
        
        # Delete from database
        await db.delete(tenant_schema)
        await db.commit()
        
        # Clear cache
        await redis_manager.client.delete(f"tenant:metrics:{tenant_id}")
        
        logger.info("Tenant deleted", tenant_id=tenant_id)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to delete tenant",
            tenant_id=tenant_id,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete tenant: {str(e)}"
        ) 