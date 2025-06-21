import redis.asyncio as redis
import json
import logging
import uuid
from typing import Any, Optional, Dict
from common.config import settings

logger = logging.getLogger(__name__)

class RedisManager:
    def __init__(self, redis_url: str = None):
        self.redis_url = str(redis_url) if redis_url else str(settings.redis_url)
        self.redis_client = None
    async def connect(self):
        """Connect to Redis using production-ready settings."""
        try:
            logger.debug(f"Attempting Redis connection with URL: {self.redis_url}")
            # Production-ready Redis configuration
            self.redis_client = redis.from_url(
                self.redis_url,
                encoding='utf-8',
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis_client:
            await self.redis_client.aclose()
            logger.info("Disconnected from Redis")
    async def set(self, key:str, value:Any, expire:int=None):
        """Set a key-value pair in Redis"""
        try:
            if isinstance(value, (dict, list)): 
                value = json.dumps(value)
            await self.redis_client.set(key, value, ex=expire)
            logger.info(f"Set key {key} with value {value}")
        except Exception as e:
            logger.error(f"Failed to set key {key}: {e}")
            raise
    async def get(self, key:str) -> Optional[Any]:
        """Get a value from Redis"""
        try:
            value = await self.redis_client.get(key)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except Exception as e:
            logger.error(f"Failed to get key {key}: {e}")
            raise
    async def delete(self, key:str):
        """Delete a key from Redis"""
        try:
            await self.redis_client.delete(key)
            logger.info(f"Deleted key {key}")
        except Exception as e:
            logger.error(f"Failed to delete key {key}: {e}")
            raise
    async def exist(self, key:str) -> bool:
        """Check if a key exists in Redis"""
        try:
            return await self.redis_client.exists(key)
        except Exception as e:
            logger.error(f"Failed to check key {key}: {e}")
            raise
            
    async def get_redis(self):
        """Get Redis client for dependency injection"""
        if not self.redis_client:
            await self.connect()
        return self.redis_client

    async def create_user_session(self, user_id: str, extra_data: Optional[Dict[str, Any]] = None, expire: int = 3600) -> str:
        """
        Creates a user session in Redis.
        Returns the session ID.
        """
        session_id = str(uuid.uuid4())
        session_key = f"session:{session_id}"
        session_data = {"user_id": user_id}
        if extra_data:
            session_data.update(extra_data)
        
        await self.set(session_key, session_data, expire=expire)
        logger.info(f"Created session {session_id} for user {user_id}")
        return session_id

    async def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Gets session data from Redis."""
        session_key = f"session:{session_id}"
        return await self.get(session_key)

    async def delete_session(self, session_id: str):
        """Deletes a session from Redis."""
        session_key = f"session:{session_id}"
        await self.delete(session_key)

# Global Redis Manager
redis_manager = RedisManager()