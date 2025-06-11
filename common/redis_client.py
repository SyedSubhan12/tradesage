import redis.asyncio as redis
import json
import logging
from typing import Any, Optional
from common.config import settings

logger = logging.getLogger(__name__)

class RedisManager:
    def __init__(self, redis_url: str = None):
        self.redis_url = str(redis_url) if redis_url else str(settings.redis_url)
        self.redis_client = None
    async def connect(self):
        """Connect to Redis"""
        try:
            logger.debug(f"Attempting Redis connection with URL: {self.redis_url}")
            self.redis_client = redis.from_url(
                settings.redis_url,
                encoding='utf-8',
                decode_responses=True
            )

            #Test Connection
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

# Global Redis Manager
redis_manager = RedisManager()