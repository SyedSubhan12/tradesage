# app/routers/v1/monitoring.py

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
import structlog

from tenant_service.app.schemas.tenant_schemas import TenantMetricResponse
from tenant_service.app.services.monitoring_service import TenantMonitoringService
from tenant_service.app.models.tenant import TenantSchema, TenantMetric
from common.database import db_manager
from common.redis_client import redis_manager
from common.auth import get_current_user, require_admin

logger = structlog.get_logger(__name__)

router = APIRouter()


# Dependency to get database session
async def get_db():
    async with db_manager.get_session() as session:
        yield session


# Dependency to get monitoring service
def get_monitoring_service():
    return TenantMonitoringService(db_manager.get_session, redis_manager.client)


@router.get("/{tenant_id}/metrics", response_model=Dict[str, Any])
async def get_tenant_metrics(
    tenant_id: str,
    refresh: bool = Query(False, description="Force refresh metrics from database"),
    db: AsyncSession = Depends(get_db),
    monitoring_service: TenantMonitoringService = Depends(get_monitoring_service),
    current_user = Depends(get_current_user)
):
    """
    Get current metrics for a tenant.
    
    Returns storage, performance, and usage metrics.
    """
    # Verify tenant exists
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    # Get metrics
    if refresh:
        # Force collection of fresh metrics
        metrics = await monitoring_service.collect_tenant_metrics(
            tenant_id, 
            tenant_schema.schema_name
        )
    else:
        # Get from cache/database
        metrics = await monitoring_service.get_tenant_metrics(tenant_id)
    
    if not metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No metrics found for tenant"
        )
    
    return metrics


@router.get("/{tenant_id}/metrics/history", response_model=List[TenantMetricResponse])
async def get_metrics_history(
    tenant_id: str,
    metric_type: Optional[str] = Query(None, description="Filter by metric type"),
    hours: int = Query(24, ge=1, le=168, description="Hours of history to retrieve"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get historical metrics for a tenant.
    
    Returns metrics collected over the specified time period.
    """
    # Verify tenant exists
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    # Build query
    query = select(TenantMetric).where(
        TenantMetric.tenant_id == tenant_id,
        TenantMetric.collected_at >= datetime.utcnow() - timedelta(hours=hours)
    )
    
    if metric_type:
        query = query.where(TenantMetric.metric_type == metric_type)
    
    query = query.order_by(TenantMetric.collected_at.desc())
    
    # Execute
    result = await db.execute(query)
    metrics = result.scalars().all()
    
    return [TenantMetricResponse.from_orm(m) for m in metrics]


@router.get("/{tenant_id}/health", response_model=Dict[str, Any])
async def get_tenant_health(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    monitoring_service: TenantMonitoringService = Depends(get_monitoring_service),
    current_user = Depends(get_current_user)
):
    """
    Get tenant health status.
    
    Returns overall health score and individual component statuses.
    """
    # Verify tenant exists
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    # Get health status
    health_status = await monitoring_service.get_tenant_health_status(tenant_id)
    
    # Get latest metrics for details
    metrics = await monitoring_service.get_tenant_metrics(tenant_id)
    
    # Build health response
    health_response = {
        "tenant_id": tenant_id,
        "status": health_status,
        "checked_at": datetime.utcnow().isoformat(),
        "is_active": tenant_schema.is_active,
        "components": {}
    }
    
    if metrics:
        # Storage health
        if "storage" in metrics:
            storage = metrics["storage"]
            size_bytes = storage.get("size_bytes", 0)
            size_limit = 10 * 1024 * 1024 * 1024  # 10GB
            usage_percent = (size_bytes / size_limit) * 100
            
            health_response["components"]["storage"] = {
                "status": "healthy" if usage_percent < 80 else "warning" if usage_percent < 90 else "critical",
                "usage_percent": round(usage_percent, 2),
                "size": storage.get("total_size", "0 bytes")
            }
        
        # Performance health
        if "performance" in metrics:
            perf = metrics["performance"]
            avg_query_time = perf.get("avg_query_time_ms", 0)
            
            health_response["components"]["performance"] = {
                "status": "healthy" if avg_query_time < 100 else "warning" if avg_query_time < 500 else "critical",
                "avg_query_time_ms": avg_query_time,
                "active_connections": perf.get("active_connections", 0),
                "cache_hit_ratio": perf.get("cache_hit_ratio", 0)
            }
        
        # Usage health
        if "usage" in metrics:
            usage = metrics["usage"]
            health_response["components"]["usage"] = {
                "status": "healthy",
                "total_rows": usage.get("total_rows", 0),
                "transactions": usage.get("transactions", {})
            }
    
    return health_response


@router.get("/dashboard", response_model=Dict[str, Any])
async def get_monitoring_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Get system-wide monitoring dashboard.
    
    Admin only. Returns aggregated metrics for all tenants.
    """
    # Get all active tenants
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.is_active == True)
    )
    tenants = result.scalars().all()
    
    # Aggregate metrics
    dashboard = {
        "total_tenants": len(tenants),
        "active_tenants": len([t for t in tenants if t.is_active]),
        "total_storage_bytes": 0,
        "avg_query_time_ms": 0,
        "total_connections": 0,
        "tenants_by_health": {
            "healthy": 0,
            "degraded": 0,
            "unhealthy": 0,
            "unknown": 0
        },
        "updated_at": datetime.utcnow().isoformat()
    }
    
    monitoring_service = get_monitoring_service()
    
    # Collect metrics for each tenant
    query_times = []
    for tenant in tenants:
        try:
            metrics = await monitoring_service.get_tenant_metrics(str(tenant.tenant_id))
            if metrics:
                # Storage
                if "storage" in metrics:
                    dashboard["total_storage_bytes"] += metrics["storage"].get("size_bytes", 0)
                
                # Performance
                if "performance" in metrics:
                    query_time = metrics["performance"].get("avg_query_time_ms", 0)
                    if query_time > 0:
                        query_times.append(query_time)
                    dashboard["total_connections"] += metrics["performance"].get("active_connections", 0)
            
            # Health status
            health = await monitoring_service.get_tenant_health_status(str(tenant.tenant_id))
            dashboard["tenants_by_health"][health] += 1
            
        except Exception as e:
            logger.error(
                "Failed to get metrics for tenant",
                tenant_id=str(tenant.tenant_id),
                error=str(e)
            )
            dashboard["tenants_by_health"]["unknown"] += 1
    
    # Calculate averages
    if query_times:
        dashboard["avg_query_time_ms"] = sum(query_times) / len(query_times)
    
    # Format storage
    dashboard["total_storage_gb"] = round(dashboard["total_storage_bytes"] / (1024**3), 2)
    
    return dashboard


@router.post("/{tenant_id}/metrics/collect", status_code=status.HTTP_202_ACCEPTED)
async def trigger_metrics_collection(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    monitoring_service: TenantMonitoringService = Depends(get_monitoring_service),
    current_user = Depends(require_admin)
):
    """
    Manually trigger metrics collection for a tenant.
    
    Admin only. Forces immediate collection of all metrics.
    """
    # Verify tenant exists
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
        # Collect metrics
        await monitoring_service.collect_tenant_metrics(
            tenant_id,
            tenant_schema.schema_name
        )
        
        return {
            "message": "Metrics collection triggered",
            "tenant_id": tenant_id,
            "triggered_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(
            "Failed to collect metrics",
            tenant_id=tenant_id,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to collect metrics: {str(e)}"
        ) 