import uuid
from common.config import settings
import asyncio
import json
import zlib
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
from contextlib import asynccontextmanager
import logging
from enum import Enum

import redis.asyncio as redis
from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer, Boolean, Index, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from cryptography.fernet import Fernet
from ..config.session_config import SessionConfig
from ..models.session_data import SessionData


# ==================== REDIS CACHE LAYER ====================

async def _get_redis_client(self) -> redis.Redis:
    """Get Redis client from pool"""
    return redis.Redis(connection_pool=self.redis_pool)

async def _release_redis_client(self, client:redis.Redis):
    """Cache Session in Redis with TTL"""
    try:
        redis_client = await self._get_redis_client()
        
        # primary cache key
        cache_key = f"session:{session_id}"
        serialized_data = self._serialize_session_data(session_data)

        # store with ttl
        await redis_client.setex(cache_key, self.config.redis_ttl, serialized_data)

        # secondary index by user_id for quick lookups
        user_sessions_key = f"user_sessions:{session_data.user_id}"
        await redis_client.sadd(user_sessions_key, session_id)

        # update last_active_time
        await redis_client.hset(cache_key, "last_active_time", datetime.utcnow().isoformat())

        # update ttl for primary key
        await redis_client.expire(cache_key, self.config.redis_ttl)

        # update ttl for secondary index
        await redis_client.expire(user_sessions_key, self.config.redis_ttl)
        
        # store session_id in user_sessions index
        metadata_key = f"Session_meta:{session_id}"
        metadata = {
            "user_id": session_data.user_id,
            "created_at": session_data.created_at,
            "last_active_time": session_data.last_active_time,
            "last_updated": session_data.last_updated,
            "checksum": session_data.checksum,
            "session_id": session_id,
            "version": session_data.version,
        }
        await redis_client.hset(metadata_key, mapping=metadata)
        await redis_client.expire(metadata_key, self.config.cache_ttl)
        await redis_client.close()
        
    except Exception as e:
        self.logger.error(f"Failed to cache session: {str(e)}")
        return False
    finally:    
        await self._release_redis_client(redis_client)
    
async def _get_cached_session(self, session_id : str) -> Optional[SessionData]:
    """Retrieve session from cache"""
    try:
        redis_client = await self._get_redis_client()

        cache_key = f"session:{session_id}"
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            return self._deserialize_session_data(cached_data.decode())
        return None
    except Exception as e:
        self.logger.error(f"Failed to retrieve session cached {session_id}: {str(e)}")   
        return None
    finally:
        await self._release_redis_client(redis_client)
async def _invalidate_cache(self, session_id : str) -> bool:
    """Invalidate session cache"""
    try:
        redis_client = await self._get_redis_client()
        
        # remove all the related keys
        await redis_client.delete(f"session:{session_id}")
        await redis_client.delete(f"user_sessions:{session_id}")
        await redis_client.delete(f"session_meta:{user_id}", session_id)
        
        await redis_client.close()
       
    except Exception as e:
        self.logger.error(f"Failed to invalidate session cache {session_id}: {str(e)}")
       
    finally:
        await self._release_redis_client(redis_client)  