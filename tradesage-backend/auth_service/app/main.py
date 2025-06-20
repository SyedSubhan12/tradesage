# main.py

import sys
import os

# add root directory to path for common module imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import text
from datetime import datetime, timezone
import logging
import asyncio

from common.config import settings
from contextlib import asynccontextmanager
from common.database import db_manager
from common.redis_client import redis_manager
from common.logging_config import setup_logging

# Import middlewares
from auth_service.app.middlewares.rate_limit import RateLimitMiddleware
from auth_service.app.middlewares.tenant_isolation import TenantIsolationMiddleware

# Import routers
from auth_service.app.routers.v1.auth import router as auth_router
from auth_service.app.routers.v1.users import router as users_router
from auth_service.app.routers.v1.tenant import router as tenant_router
from auth_service.app.routers.v1.oauth import router as oauth_router

# Import services
from auth_service.app.services.auth_service import cleanup_expired_tokens

# setup logging
setup_logging()
logger = logging.getLogger("tradesage.auth")


# ================================
# LIFESPAN MANAGEMENT
# ================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        await redis_manager.connect()
        logger.info("Redis connection established")
        
        # Ensure tables (including tenant index) exist
        async with db_manager.engine.begin() as conn:
            from common.models import Base
            await conn.run_sync(Base.metadata.create_all)
            # Create an index on tenants(status) for faster lookups
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status)"
            ))
        logger.info("Database tables verified/created with tenant index")
        
        # Schedule cleanup task
        async def periodic_cleanup():
            while True:
                try:
                    await asyncio.sleep(3600)  # Run every hour
                    db = await db_manager.get_session()
                    await cleanup_expired_tokens(db)
                    await db.close()
                except Exception as e:
                    logger.error(f"Periodic cleanup error: {e}")
        
        cleanup_task = asyncio.create_task(periodic_cleanup())
        logger.info("Auth Service Started")
        yield
        # Shutdown
        cleanup_task.cancel()
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise
    finally:
        try:
            await redis_manager.disconnect()
            logger.info("Disconnected from Redis")
        except Exception:
            logger.error("Error disconnecting Redis")
        try:
            await db_manager.close()
            logger.info("Database connection closed")
        except Exception:
            logger.error("Error closing DB manager")
        logger.info("Auth Service Shutdown")


# ================================
# FASTAPI APP SETUP
# ================================
app = FastAPI(
    title="TradeSage Authentication Service",
    description="Authentication and authorization microservice for TradeSage",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, 'CORS_ORIGINS', ["*"]),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(TenantIsolationMiddleware)
app.add_middleware(RateLimitMiddleware)


# ================================
# EXCEPTION HANDLERS
# ================================
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    error_messages = []
    
    for error in errors:
        # Handle role validation errors specifically
        if error.get("loc") and len(error["loc"]) > 1 and error["loc"][1] == "role":
            error_messages.append({
                "field": "role",
                "message": "Invalid role. Please use one of: admin, trader, viewer, or api_user",
                "provided": error.get("input")
            })
        else:
            error_messages.append({
                "field": error.get("loc", [""])[-1],
                "message": error.get("msg", "Validation error"),
                "provided": error.get("input")
            })
    
    logger.warning(f"Validation error on {request.url.path}: {error_messages}")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Validation error", "errors": error_messages}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # If tenant-related error, return 400 with generic tenant message
    if "tenant" in str(exc).lower():
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Tenant account issue - contact administrator"}
        )
    logger.error(f"Unhandled error on {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ================================
# HEALTH CHECK ENDPOINT
# ================================
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "ok",
        "version": "1.0.0",
        "service": "auth_service",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ================================
# INCLUDE ROUTERS
# ================================
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(tenant_router)
app.include_router(oauth_router)


# Print all registered routes at startup
for route in app.routes:
    print(f"Path: {route.path}, Methods: {route.methods}")


# ================================
# RUN WITH UVIORN IF MAIN
# ================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("__main__:app", host="127.0.0.1", port=8000, reload=True, log_level='info')
