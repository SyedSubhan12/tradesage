"""
Session Validation Caching Service

This module provides caching and fallback mechanisms for session validation
to improve resilience when the session service is unavailable.
"""

import asyncio
import time
from functools import lru_cache
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from auth_service.app.clients.session_client import session_service_client
from common.models.user_session import UserSession, SessionState
from common.database import db_manager

logger = structlog.get_logger("tradesage.auth.session_cache")

# Global cache for session validation results with TTL
_session_cache: Dict[str, Dict[str, Any]] = {}
_cache_ttl_seconds = 60  # 1 minute cache TTL

class SessionValidationCache:
    """Enhanced session validation with caching and fallback mechanisms"""
    
    def __init__(self, cache_ttl_seconds: int = 60):
        self.cache_ttl_seconds = cache_ttl_seconds
        self.logger = logger.bind(component="session_cache")
    
    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if a cache entry is still valid"""
        if not cache_entry:
            return False
        
        cached_at = cache_entry.get("cached_at", 0)
        return (time.time() - cached_at) < self.cache_ttl_seconds
    
    def _cache_session_result(self, session_id: str, user_id: str, is_valid: bool, session_data: Optional[Dict] = None):
        """Cache a session validation result"""
        global _session_cache
        
        cache_key = f"{session_id}:{user_id}"
        _session_cache[cache_key] = {
            "is_valid": is_valid,
            "session_data": session_data,
            "cached_at": time.time()
        }
        
        self.logger.debug(
            "Session validation result cached",
            session_id=session_id,
            user_id=user_id,
            is_valid=is_valid
        )
    
    def _get_cached_result(self, session_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a cached session validation result if valid"""
        global _session_cache
        
        cache_key = f"{session_id}:{user_id}"
        cache_entry = _session_cache.get(cache_key)
        
        if cache_entry and self._is_cache_valid(cache_entry):
            self.logger.debug(
                "Using cached session validation result",
                session_id=session_id,
                user_id=user_id
            )
            return cache_entry
        
        # Clean up expired entry
        if cache_entry:
            del _session_cache[cache_key]
        
        return None
    
    async def validate_session_in_database(self, session_id: str, user_id: str) -> bool:
        """Fallback: Validate session directly in database"""
        try:
            self.logger.debug(
                "Validating session in database (fallback)",
                session_id=session_id,
                user_id=user_id
            )
            
            async with db_manager.get_session() as db:
                result = await db.execute(
                    select(UserSession).where(
                        UserSession.id == session_id,
                        UserSession.user_id == user_id,
                        UserSession.state == SessionState.ACTIVE.value,
                        UserSession.expires_at > datetime.now(timezone.utc)
                    )
                )
                session = result.scalar_one_or_none()
                
                is_valid = session is not None
                
                self.logger.info(
                    "Database session validation completed",
                    session_id=session_id,
                    user_id=user_id,
                    is_valid=is_valid
                )
                
                return is_valid
                
        except Exception as e:
            self.logger.error(
                "Database session validation failed",
                session_id=session_id,
                user_id=user_id,
                error=str(e)
            )
            return False
    
    async def cached_session_validation(self, session_id: str, user_id: str) -> bool:
        """
        Validate session with caching and fallback mechanisms
        
        Args:
            session_id: Session ID to validate
            user_id: User ID that should own the session
            
        Returns:
            bool: True if session is valid, False otherwise
        """
        # Check cache first
        cached_result = self._get_cached_result(session_id, user_id)
        if cached_result is not None:
            return cached_result["is_valid"]
        
        # Try session service
        try:
            self.logger.debug(
                "Validating session via session service",
                session_id=session_id,
                user_id=user_id
            )
            
            session_info = await session_service_client.get_session(session_id)
            
            if session_info and session_info.get("user_id") == user_id:
                # Check if session is expired
                expires_at_str = session_info.get("expires_at")
                if expires_at_str:
                    try:
                        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                        if expires_at < datetime.now(timezone.utc):
                            is_valid = False
                        else:
                            is_valid = True
                    except ValueError:
                        is_valid = False
                else:
                    is_valid = True
                
                # Cache the result
                self._cache_session_result(session_id, user_id, is_valid, session_info)
                
                self.logger.info(
                    "Session service validation completed",
                    session_id=session_id,
                    user_id=user_id,
                    is_valid=is_valid
                )
                
                return is_valid
            else:
                # Session not found or user mismatch
                self._cache_session_result(session_id, user_id, False, None)
                return False
                
        except Exception as e:
            self.logger.warning(
                "Session service validation failed, falling back to database",
                session_id=session_id,
                user_id=user_id,
                error=str(e)
            )
            
            # Fallback to database validation
            is_valid = await self.validate_session_in_database(session_id, user_id)
            
            # Cache the result with shorter TTL for fallback results
            self._cache_session_result(session_id, user_id, is_valid, None)
            
            return is_valid
    
    def clear_cache(self):
        """Clear the entire session cache"""
        global _session_cache
        _session_cache.clear()
        self.logger.info("Session validation cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        global _session_cache
        
        total_entries = len(_session_cache)
        valid_entries = sum(1 for entry in _session_cache.values() if self._is_cache_valid(entry))
        
        return {
            "total_entries": total_entries,
            "valid_entries": valid_entries,
            "expired_entries": total_entries - valid_entries,
            "cache_ttl_seconds": self.cache_ttl_seconds
        }

# Global instance
session_cache = SessionValidationCache()

# Backward compatible function
async def cached_session_validation(session_id: str, user_id: str) -> bool:
    """
    Cache session validation for 60 seconds with fallback to database
    
    This function provides a resilient session validation mechanism that:
    1. First checks an in-memory cache
    2. Falls back to the session service
    3. Falls back to direct database validation if service is unavailable
    4. Caches results to reduce load on downstream services
    """
    return await session_cache.cached_session_validation(session_id, user_id)

# Cleanup task to remove expired cache entries
async def cleanup_expired_cache_entries():
    """Background task to clean up expired cache entries"""
    global _session_cache
    
    while True:
        try:
            current_time = time.time()
            expired_keys = [
                key for key, entry in _session_cache.items()
                if (current_time - entry.get("cached_at", 0)) > _cache_ttl_seconds
            ]
            
            for key in expired_keys:
                del _session_cache[key]
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
            
            # Run cleanup every 5 minutes
            await asyncio.sleep(300)
            
        except Exception as e:
            logger.error(f"Error in cache cleanup task: {e}")
            await asyncio.sleep(60)  # Retry after 1 minute on error 