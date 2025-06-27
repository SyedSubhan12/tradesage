import redis.asyncio as redis
from fastapi import Depends
from common.database import db_manager
from common.config import settings
from .services.session_service import SessionService
import redis.asyncio as redis

async def get_redis_client() -> redis.Redis:
    try:
        # Ensure the redis_url is a string for from_url
        redis_client = redis.from_url(str(settings.redis_url), encoding="utf-8", decode_responses=True)
        yield redis_client
    finally:
        await redis_client.close()

def get_session_service(
    redis_client: redis.Redis = Depends(get_redis_client),
) -> SessionService:
    """Dependency injector for the SessionService."""
    # The db_manager is a singleton; its factory is initialized once.
    return SessionService(
        session_factory=db_manager.async_session,
        redis_client=redis_client,
        encryption_key=settings.session_encryption_key,
        config=settings,
    )
