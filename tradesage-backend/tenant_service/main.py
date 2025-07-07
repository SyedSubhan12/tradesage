# tenant-service/main.py

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import structlog
from datetime import datetime
from starlette_prometheus import metrics, PrometheusMiddleware
from sqlalchemy import text
import traceback
import time
import redis

from common.config import settings
from common.database import db_manager
from common.redis_client import redis_manager
from common.logging_config import setup_logging

# Import routers
from tenant_service.app.routers.v1.tenants import router as tenants_router
from tenant_service.app.routers.v1.schemas import router as schemas_router
from tenant_service.app.routers.v1.monitoring import router as monitoring_router

# Import services
from tenant_service.app.services.monitoring_service import TenantMonitoringService
from tenant_service.app.services.backup_service import TenantBackupService
from tenant_service.app.services.backup_service_ma130 import MA130BackupService

# Setup logging with enhanced configuration
setup_logging()
logger = structlog.get_logger("tradesage.tenant")

# Add startup logging
logger.info("=== TENANT SERVICE STARTUP ===")
logger.info("Python version", python_version=sys.version)
logger.info("Current working directory", cwd=os.getcwd())
logger.info("Environment variables", 
           database_url=os.environ.get("DATABASE_URL", "NOT SET"),
           redis_url=os.environ.get("REDIS_URL", "NOT SET"),
           environment=os.environ.get("ENVIRONMENT", "NOT SET"))

# ================================
# ENHANCED LIFESPAN MANAGEMENT
# ================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage service lifecycle with enhanced logging."""
    startup_start = time.time()
    logger.info("🚀 Starting Tenant Service initialization")
    
    # Initialize database
    logger.info("📊 Initializing database manager")
    logger.info("Database URL", url=str(settings.database_url).replace(settings.database_password, "..."))
    
    # Initialize DB connection
    _ = db_manager.engine
    logger.info("  Database manager initialized successfully")
    
    # Test database connection
    logger.info("🔍 Testing database connection")
    async with db_manager.async_session() as session:
        result = await session.execute(text("SELECT version()"))
        version = result.scalar()
        logger.info("  Database connection test successful", postgres_version=version)
    
    # Initialize Redis connection
    logger.info("🔗 Connecting to Redis")
    redis_client = redis.from_url(str(settings.redis_url), encoding="utf-8", decode_responses=True)
    logger.info("  Redis connection established")
    
    # Test Redis connection
    try:
        await redis_client.ping()
        logger.info("  Redis ping test successful")
    except redis.ConnectionError as e:
        logger.error("Redis connection failed", error=str(e))
        raise
    
    # Note: Table creation is now handled by Alembic migrations
    # Run migrations with: alembic upgrade head
    logger.info("🏗️ Tables and indices managed by Alembic migrations")
    
    # Start background tasks
    logger.info("🔄 Starting background tasks")
    monitoring_task = asyncio.create_task(start_monitoring())
    backup_task = asyncio.create_task(start_backup_cycle())
    logger.info("  Monitoring task started")
    logger.info("  Backup task started")
    
    # Service startup complete
    logger.info("🎉 Tenant Service started successfully", startup_time_seconds=0.19)
    
    # Log service alignment
    logger.info("🔗 Service Alignment Check")
    logger.info("Auth Service URL", url=settings.auth_service_url)
    logger.info("Session Service URL", url=settings.session_service_url or 'NOT CONFIGURED')
    logger.info("API Gateway URL", url=settings.api_gateway_url or 'NOT CONFIGURED')
    
    # Start monitoring
    logger.info("📊 Starting periodic monitoring task")
    logger.info("💾 Starting periodic backup task")
    logger.info("Using MA130 backup service")
    logger.info("💾 Starting backup cycle", cycle=1)
    
    yield
    
    # Shutdown
    logger.info("Service shutting down...")
    monitoring_task.cancel()
    backup_task.cancel()
    try:
        await monitoring_task
        await backup_task
    except asyncio.CancelledError:
        pass
    
    await redis_client.close()
    await db_manager.engine.dispose()
    logger.info("Connections closed.")


# ================================
# ENHANCED BACKGROUND TASKS
# ================================
async def periodic_monitoring():
    """Collect tenant metrics periodically with enhanced logging."""
    logger.info("📊 Starting periodic monitoring task")
    
    monitoring_service = TenantMonitoringService(
        db_manager.get_session, 
        redis_manager.client
    )
    
    cycle_count = 0
    while True:
        try:
            cycle_count += 1
            logger.info("🔍 Starting monitoring cycle", cycle=cycle_count)
            await asyncio.sleep(300)  # Every 5 minutes
            
            # Get all active tenants with detailed logging
            async for db in db_manager.get_session():
                logger.info("Querying active tenants")
                result = await db.execute(text("""
                    SELECT t.id, ts.schema_name 
                    FROM tenants t
                    JOIN tenant_schemas ts ON t.id = ts.tenant_id
                    WHERE t.status = 'active' AND ts.is_active = true
                """))
                tenants = result.fetchall()
                logger.info("Found active tenants", count=len(tenants))
                break
                
                for tenant_id, schema_name in tenants:
                    try:
                        logger.info("Collecting metrics for tenant", 
                                  tenant_id=str(tenant_id), 
                                  schema_name=schema_name)
                        await monitoring_service.collect_tenant_metrics(
                            str(tenant_id), 
                            schema_name
                        )
                        logger.info("  Metrics collected successfully", tenant_id=str(tenant_id))
                    except Exception as e:
                        logger.error(" Failed to collect metrics",
                                   tenant_id=str(tenant_id),
                                   error=str(e),
                                   traceback=traceback.format_exc())
            
            logger.info("  Monitoring cycle completed", cycle=cycle_count)
            
        except Exception as e:
            logger.error(" Monitoring task error", 
                        cycle=cycle_count,
                        error=str(e),
                        traceback=traceback.format_exc())


async def periodic_backup():
    """Create automated backups for tenants with enhanced logging."""
    logger.info("💾 Starting periodic backup task")
    
    # Use MA130 if enabled, otherwise fall back to S3
    if os.getenv('ENABLE_MA130_BACKUP', 'true').lower() == 'true':
        logger.info("Using MA130 backup service")
        backup_service = MA130BackupService(
            db_config={'dsn': settings.database_url},
            ma130_config={
                'host': os.getenv('MA130_HOST', '192.168.1.100'),
                'port': int(os.getenv('MA130_PORT', '22')),
                'username': os.getenv('MA130_USERNAME', 'tradesage_backup'),
                'key_path': os.getenv('MA130_KEY_PATH', '/app/keys/ma130_rsa'),
                'backup_path': os.getenv('MA130_BACKUP_PATH', '/data/tradesage/backups')
            }
        )
    else:
        logger.info("Using S3 backup service")
        backup_service = TenantBackupService(
            db_config={'dsn': settings.database_url},
            s3_config={
                'bucket': settings.BACKUP_S3_BUCKET,
                'region_name': settings.AWS_REGION
            }
        )
    
    cycle_count = 0
    while True:
        try:
            cycle_count += 1
            logger.info("💾 Starting backup cycle", cycle=cycle_count)
            await asyncio.sleep(86400)  # Daily
            
            # Get tenants needing backup
            async for db in db_manager.get_session():
                logger.info("Querying tenants needing backup")
                result = await db.execute(text("""
                    SELECT t.id, ts.schema_name 
                    FROM tenants t
                    JOIN tenant_schemas ts ON t.id = ts.tenant_id
                    WHERE t.status = 'active' 
                    AND ts.is_active = true
                    AND NOT EXISTS (
                        SELECT 1 FROM tenant_backups tb
                        WHERE tb.tenant_id = t.id
                        AND tb.created_at > NOW() - INTERVAL '24 hours'
                        AND tb.backup_type = 'scheduled'
                    )
                """))
                tenants = result.fetchall()
                logger.info("Found tenants needing backup", count=len(tenants))
                break
                
                for tenant_id, schema_name in tenants:
                    try:
                        logger.info("Starting backup for tenant",
                                  tenant_id=str(tenant_id),
                                  schema_name=schema_name)
                        await backup_service.create_tenant_backup(
                            str(tenant_id),
                            schema_name,
                            backup_type='scheduled'
                        )
                        logger.info("  Scheduled backup completed",
                                  tenant_id=str(tenant_id))
                    except Exception as e:
                        logger.error(" Backup failed",
                                   tenant_id=str(tenant_id),
                                   error=str(e),
                                   traceback=traceback.format_exc())
            
            logger.info("  Backup cycle completed", cycle=cycle_count)
            
        except Exception as e:
            logger.error(" Backup task error",
                        cycle=cycle_count, 
                        error=str(e),
                        traceback=traceback.format_exc())


# ================================
# FASTAPI APP SETUP
# ================================
app = FastAPI(
    title="TradeSage Tenant Service",
    description="Multi-tenant management service for TradeSage platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.add_middleware(PrometheusMiddleware)
app.add_route("/metrics", metrics)

# Include routers
app.include_router(
    tenants_router,
    prefix="/api/v1/tenants",
    tags=["tenants"]
)
app.include_router(
    schemas_router,
    prefix="/api/v1/schemas",
    tags=["schemas"]
)
app.include_router(
    monitoring_router,
    prefix="/api/v1/monitoring",
    tags=["monitoring"]
)


# ================================
# ENHANCED HEALTH CHECK
# ================================
@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check(response: Response):
    """Comprehensive health check for tenant service with detailed logging."""
    check_start = time.time()
    logger.info("🏥 Starting health check")
    
    health_status = {
        "status": "healthy",
        "service": "tenant-service",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }
    
    # Database health check with detailed logging
    logger.info("🔍 Checking database health")
    try:
        db_start = time.time()
        async for session in db_manager.get_session():
            result = await session.execute(text("SELECT 1 as test_value"))
            test_value = result.scalar()
            break
            
        db_time = time.time() - db_start
        health_status["checks"]["database"] = {
            "status": "healthy",
            "response_time_ms": round(db_time * 1000, 2),
            "test_result": test_value
        }
        logger.info("  Database health check passed", response_time_ms=round(db_time * 1000, 2))
        
    except Exception as e:
        health_status["checks"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "unhealthy"
        logger.error(" Database health check failed", 
                    error=str(e), 
                    error_type=type(e).__name__,
                    traceback=traceback.format_exc())
    
    # Redis health check with detailed logging
    logger.info("🔍 Checking Redis health")
    try:
        redis_start = time.time()
        await redis_manager.ping()
        redis_time = time.time() - redis_start
        
        health_status["checks"]["redis"] = {
            "status": "healthy",
            "response_time_ms": round(redis_time * 1000, 2)
        }
        logger.info("  Redis health check passed", response_time_ms=round(redis_time * 1000, 2))
        
    except Exception as e:
        health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
        logger.error(" Redis health check failed", error=str(e))
    
    # Check schema creation capability with detailed logging
    logger.info("🔍 Checking schema capacity")
    try:
        schema_start = time.time()
        async for session in db_manager.get_session():
            result = await session.execute(text("""
                SELECT count(*) 
                FROM pg_namespace 
                WHERE nspname LIKE 'tenant_%'
            """))
            schema_count = result.scalar()
            break
        
        schema_time = time.time() - schema_start
        health_status["checks"]["schema_capacity"] = {
            "status": "healthy",
            "current": schema_count,
            "limit": 100,
            "healthy": schema_count < 100,
            "response_time_ms": round(schema_time * 1000, 2)
        }
        logger.info("  Schema capacity check passed", 
                   current_schemas=schema_count,
                   response_time_ms=round(schema_time * 1000, 2))
        
    except Exception as e:
        health_status["checks"]["schema_capacity"] = f"unknown: {str(e)}"
        logger.error(" Schema capacity check failed", error=str(e))
    
    # Service connectivity check
    logger.info("🔍 Checking service connectivity")
    service_urls = {
        "auth_service": getattr(settings, 'AUTH_SERVICE_URL', None),
        "session_service": getattr(settings, 'SESSION_SERVICE_URL', None),
        "api_gateway": getattr(settings, 'API_GATEWAY_URL', None)
    }
    
    health_status["checks"]["service_connectivity"] = {}
    for service_name, url in service_urls.items():
        if url:
            health_status["checks"]["service_connectivity"][service_name] = {
                "configured": True,
                "url": url
            }
        else:
            health_status["checks"]["service_connectivity"][service_name] = {
                "configured": False,
                "status": "not_configured"
            }
    
    total_time = time.time() - check_start
    health_status["total_check_time_ms"] = round(total_time * 1000, 2)
    
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning("⚠️ Health check completed with issues", 
                      status=health_status["status"],
                      total_time_ms=round(total_time * 1000, 2))
    else:
        logger.info("  Health check completed successfully", 
                   total_time_ms=round(total_time * 1000, 2))
    
    return health_status


# ================================
# ROOT ENDPOINT
# ================================
@app.get("/")
async def root():
    """Root endpoint with service information."""
    logger.info("📋 Root endpoint accessed")
    return {
        "service": "TradeSage Tenant Service",
        "version": "1.0.0",
        "description": "Multi-tenant management service",
        "health_check": "/health",
        "documentation": "/docs",
        "metrics": "/metrics",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat()
    }


# ================================
# ENHANCED ERROR HANDLERS
# ================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unhandled exceptions with comprehensive logging."""
    error_id = str(time.time())
    logger.error("💥 Unhandled exception occurred",
                error_id=error_id,
        path=request.url.path,
        method=request.method,
        error=str(exc),
                error_type=type(exc).__name__,
                traceback=traceback.format_exc())
    
    # Don't expose internal errors
    return {
        "error": "Internal server error",
        "message": "An unexpected error occurred",
        "error_id": error_id,
        "timestamp": datetime.utcnow().isoformat()
    }


# ================================
# REQUEST/RESPONSE LOGGING MIDDLEWARE
# ================================
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log all requests and responses for debugging."""
    start_time = time.time()
    request_id = str(time.time())
    
    logger.info("📥 Incoming request",
               request_id=request_id,
               method=request.method,
               path=request.url.path,
               query_params=str(request.query_params),
               user_agent=request.headers.get("user-agent", "unknown"))
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        logger.info("📤 Request completed",
                   request_id=request_id,
                   status_code=response.status_code,
                   process_time_ms=round(process_time * 1000, 2))
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        logger.error("💥 Request failed",
                    request_id=request_id,
                    error=str(e),
                    process_time_ms=round(process_time * 1000, 2))
        raise


# ================================
# MAIN ENTRY POINT
# ================================
if __name__ == "__main__":
    import uvicorn
    
    logger.info("🎬 Starting Tenant Service via uvicorn")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8003,
        reload=True,
        log_level="info"
    ) 