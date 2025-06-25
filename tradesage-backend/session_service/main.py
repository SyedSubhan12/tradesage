import sys
import os
import asyncio
import structlog
from contextlib import asynccontextmanager

# Add project root to path for common module imports
# This allows running the service from the service's directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import session
from app.services.session_service import SessionService
from common.database import db_manager
from common.config import settings
from common.logging_config import setup_logging
import redis.asyncio as redis

# Setup logging
setup_logging()
logger = structlog.get_logger("tradesage.session")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Session service starting up...")
    
    # Initialize DB and Redis client for the background task
    _ = db_manager.engine
    redis_client = redis.from_url(str(settings.redis_url), encoding="utf-8", decode_responses=True)
    
    # Manually create service instance for the background task
    session_service = SessionService(
        session_factory=db_manager.session_factory,
        redis_client=redis_client,
        encryption_key=settings.session_encryption_key,
        config=settings,
    )
    logger.info("Dependencies for background task created.")

    async def periodic_cleanup():
        cleanup_interval = getattr(settings, 'session_cleanup_interval_seconds', 3600)
        while True:
            await asyncio.sleep(cleanup_interval)
            try:
                logger.info("Starting periodic session cleanup...")
                await session_service.cleanup_expired_sessions()
            except Exception as e:
                logger.error("Periodic session cleanup failed", error=e, exc_info=True)

    cleanup_task = asyncio.create_task(periodic_cleanup())
    logger.info("Periodic session cleanup task scheduled.")
    
    yield
    
    # Shutdown
    logger.info("Session service shutting down...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        logger.info("Cleanup task successfully cancelled.")
    
    await redis_client.close()
    await db_manager.engine.dispose()
    logger.info("Connections closed.")


app = FastAPI(
    title="TradeSage Session Service",
    description="Manages user sessions for the TradeSage platform.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins if settings.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(session.router, prefix="/api/v1", tags=["sessions"])

@app.get("/health")
def health_check():
    return {"status": "ok"}
